/*
 *  This file is a part of KNOSSOS.
 *
 *  (C) Copyright 2007-2016
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
 *  For further information, visit http://www.knossostool.org
 *  or contact knossos-team@mpimf-heidelberg.mpg.de
 */

#include "autosavetab.h"

#include "file_io.h"
#include "widgets/GuiConstants.h"
#include "widgets/mainwindow.h"
#include "viewer.h"

#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QSettings>

AutosaveTab::AutosaveTab(QWidget * parent) : QWidget(parent, Qt::WindowFlags() & ~Qt::WindowContextHelpButtonHint) {
    autosaveIntervalSpinBox.setMinimum(1);
    autosaveIntervalSpinBox.setSuffix(" min");
    autosaveLocationEdit.setText(QFileInfo(annotationFileDefaultPath()).dir().absolutePath());
    autosaveLocationEdit.setWordWrap(true);
    autosaveLocationEdit.setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);

    mainLayout.addWidget(&autosaveCheckbox);
    formLayout.addRow(&autosaveIntervalLabel, &autosaveIntervalSpinBox);
    formLayout.setFieldGrowthPolicy(QFormLayout::FieldsStayAtSizeHint);
    mainLayout.addLayout(&formLayout);
    mainLayout.addWidget(&autoincrementFileNameButton);
    revealButton.setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    mainLayout.addWidget(&revealButton);
    mainLayout.addWidget(&autosaveLocationEdit);
    mainLayout.addStretch();
    setLayout(&mainLayout);

    QObject::connect(&autoincrementFileNameButton, &QCheckBox::stateChanged, [](const bool on) {
        Session::singleton().autoFilenameIncrementBool = on;
    });
    QObject::connect(&autosaveIntervalSpinBox, static_cast<void(QSpinBox::*)(int)>(&QSpinBox::valueChanged), [this](const int value) {
        if (autosaveCheckbox.isChecked()) {
            Session::singleton().autoSaveTimer.start(value * 60 * 1000);
        }
    });
    QObject::connect(&autosaveCheckbox, &QCheckBox::stateChanged, [this](const bool on) {
        if (on) {
            Session::singleton().autoSaveTimer.start(autosaveIntervalSpinBox.value() * 60 * 1000);
        } else {
            Session::singleton().autoSaveTimer.stop();
        }
        state->viewer->window->updateTitlebar();
    });
    QObject::connect(&revealButton, &QPushButton::clicked, [this]() {
        QDesktopServices::openUrl(QUrl::fromLocalFile(autosaveLocationEdit.text()));
    });
}

void AutosaveTab::loadSettings(const QSettings & settings) {
    autosaveIntervalSpinBox.setValue(settings.value(SAVING_INTERVAL, 5).toInt());
    autoincrementFileNameButton.setChecked(settings.value(AUTOINC_FILENAME, true).toBool());
    autosaveCheckbox.setChecked(settings.value(AUTO_SAVING, true).toBool()); // load this checkbox's state last to use loaded autosave settings in its slot
}

void AutosaveTab::saveSettings(QSettings & settings) {
    settings.setValue(AUTO_SAVING, autosaveCheckbox.isChecked());
    settings.setValue(SAVING_INTERVAL, autosaveIntervalSpinBox.value());
    settings.setValue(AUTOINC_FILENAME, autoincrementFileNameButton.isChecked());
}