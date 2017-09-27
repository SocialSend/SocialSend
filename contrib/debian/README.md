
Debian
====================
This directory contains files used to package piexd/piex-qt
for Debian-based Linux systems. If you compile piexd/piex-qt yourself, there are some useful files here.

## piex: URI support ##


piex-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install piex-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your piexqt binary to `/usr/bin`
and the `../../share/pixmaps/piex128.png` to `/usr/share/pixmaps`

piex-qt.protocol (KDE)

