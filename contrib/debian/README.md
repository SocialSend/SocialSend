
Debian
====================
This directory contains files used to package sendd/send-qt
for Debian-based Linux systems. If you compile sendd/send-qt yourself, there are some useful files here.

## send: URI support ##


send-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install send-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your sendqt binary to `/usr/bin`
and the `../../share/pixmaps/send128.png` to `/usr/share/pixmaps`

send-qt.protocol (KDE)

