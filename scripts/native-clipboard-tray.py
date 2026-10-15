#!/usr/bin/python
"""Local tray control for native-clipboard.service; never reads clipboard data."""

import os
import sys

from PySide6.QtCore import QLockFile, QProcess, QStandardPaths, QTimer
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QMenu, QStyle, QSystemTrayIcon

SERVICE = "native-clipboard.service"


class ClipboardTray(QSystemTrayIcon):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.active = None
        self.busy = False
        self.status_error_notified = False
        self.status_process = None
        self.action_process = None
        self.menu = QMenu()
        self.status_action = self.menu.addAction("Checking clipboard sync…")
        self.status_action.setEnabled(False)
        self.toggle_action = self.menu.addAction("Pause clipboard sync")
        self.toggle_action.setEnabled(False)
        self.toggle_action.triggered.connect(self.toggle)
        note = self.menu.addAction("Pause lasts until resumed or next login")
        note.setEnabled(False)
        self.menu.addSeparator()
        quit_action = QAction("Quit tray (clipboard sync keeps running)", self.menu)
        quit_action.triggered.connect(app.quit)
        self.menu.addAction(quit_action)
        self.setContextMenu(self.menu)
        self.setIcon(self.icon_for(False))
        self.setToolTip("Native Clipboard — checking service")
        self.show()
        self.timer = QTimer(self)
        self.timer.setInterval(5000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        self.refresh()

    def icon_for(self, active):
        name = "edit-paste" if active else "media-playback-pause"
        fallback = self.app.style().standardIcon(QStyle.SP_FileDialogDetailedView)
        return QIcon.fromTheme(name, fallback)

    def notify_error(self, message):
        self.showMessage("Native Clipboard", message, QSystemTrayIcon.Warning, 6000)

    def refresh(self):
        if self.status_process is not None or self.busy:
            return
        process = QProcess(self)
        self.status_process = process
        process.setProgram("/usr/bin/systemctl")
        process.setArguments(["--user", "is-active", SERVICE])
        process.finished.connect(lambda code, status: self.status_finished(process, code, status))
        process.errorOccurred.connect(lambda error: self.status_failed(process))
        QTimer.singleShot(4000, process, lambda: self.timeout(process))
        process.start()

    @staticmethod
    def timeout(process):
        if process.state() != QProcess.NotRunning:
            process.kill()

    def status_failed(self, process):
        if self.status_process is not process:
            return
        self.status_process = None
        self.active = None
        if not self.status_error_notified:
            self.notify_error("Clipboard sync status is unavailable. Check the user service installation.")
            self.status_error_notified = True
        self.status_action.setText("Clipboard sync status unavailable")
        self.toggle_action.setEnabled(False)
        self.setToolTip("Native Clipboard — service status unavailable")
        self.setIcon(self.icon_for(False))
        process.deleteLater()

    def status_finished(self, process, code, status):
        if self.status_process is not process:
            return
        state = bytes(process.readAllStandardOutput()).decode("ascii", errors="replace").strip()
        if status != QProcess.NormalExit or state not in {
            "active", "inactive", "failed", "activating", "deactivating", "reloading"
        }:
            self.status_failed(process)
            return
        self.status_process = None
        process.deleteLater()
        self.status_error_notified = False
        self.active = state in {"active", "activating", "reloading"}
        label = {
            "active": "Clipboard sync is running",
            "inactive": "Clipboard sync is paused",
            "failed": "Clipboard sync stopped with an error",
            "activating": "Clipboard sync is starting",
            "deactivating": "Clipboard sync is stopping",
            "reloading": "Clipboard sync is reloading",
        }[state]
        self.status_action.setText(label)
        self.setToolTip("Native Clipboard — " + label)
        self.setIcon(self.icon_for(self.active))
        self.toggle_action.setText("Pause clipboard sync" if self.active else "Resume clipboard sync")
        self.toggle_action.setEnabled(not self.busy and state != "deactivating")

    def toggle(self):
        if self.busy or self.active is None:
            return
        self.busy = True
        self.toggle_action.setEnabled(False)
        verb = "stop" if self.active else "start"
        process = QProcess(self)
        self.action_process = process
        process.setProgram("/usr/bin/systemctl")
        process.setArguments(["--user", verb, SERVICE])
        process.finished.connect(lambda code, status: self.action_finished(process, verb, code, status))
        process.errorOccurred.connect(lambda error: self.action_failed(process))
        QTimer.singleShot(15000, process, lambda: self.timeout(process))
        process.start()

    def action_failed(self, process):
        if self.action_process is not process:
            return
        self.action_process = None
        self.busy = False
        process.deleteLater()
        self.notify_error("Could not change clipboard sync. Check the user service status.")
        self.refresh()

    def action_finished(self, process, verb, code, status):
        if self.action_process is not process:
            return
        if status != QProcess.NormalExit or code != 0:
            self.action_failed(process)
            return
        self.action_process = None
        self.busy = False
        process.deleteLater()
        self.showMessage(
            "Native Clipboard",
            "Clipboard sync paused until resumed or next login." if verb == "stop" else "Clipboard sync resumed.",
            QSystemTrayIcon.Information,
            4000,
        )
        self.refresh()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Native Clipboard")
    app.setQuitOnLastWindowClosed(False)
    if not QSystemTrayIcon.isSystemTrayAvailable():
        return 1
    runtime = QStandardPaths.writableLocation(QStandardPaths.RuntimeLocation)
    lock = QLockFile(os.path.join(runtime, "native-clipboard-tray.lock"))
    if not lock.tryLock(0):
        return 0
    tray = ClipboardTray(app)
    app.aboutToQuit.connect(tray.hide)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
