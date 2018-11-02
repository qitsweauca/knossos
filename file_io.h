/*
 *  This file is a part of KNOSSOS.
 *
 *  (C) Copyright 2007-2018
 *  Max-Planck-Gesellschaft zur Foerderung der Wissenschaften e.V.
 *
 *  KNOSSOS is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 of
 *  the License as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *  For further information, visit https://knossos.app
 *  or contact knossos-team@mpimf-heidelberg.mpg.de
 */

#ifndef FILE_IO_H
#define FILE_IO_H

#include <QString>

#include <tuple>
#include <vector>

QString annotationFileDefaultName();
QString annotationFileDefaultPath();
void annotationFileLoad(const QString & filename, const bool mergeSkeleton, const QString & treeCmtOnMultiLoad = "");
void annotationFileSave(const QString & filename);
void nmlExport(const QString & filename);
QString updatedFileName(QString fileName);
std::vector<std::tuple<uint8_t, uint8_t, uint8_t>> loadLookupTable(const QString & path);

#endif//FILE_IO_H
