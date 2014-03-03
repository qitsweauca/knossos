#ifndef SCRIPTING_H
#define SCRIPTING_H

#include <QObject>
#include <QThread>
#include <PythonQt/PythonQt.h>
#include <PythonQt/PythonQtClassInfo.h>
#include <PythonQt/gui/PythonQtScriptingConsole.h>


class ColorDecorator;
class SkeletonDecorator;
class TreeListDecorator;
class NodeListDecorator;
class SegmentListDecorator;
class Highlighter;

/** This class intializes the python qt engine */
class Scripting : public QThread
{
    Q_OBJECT
public:

    explicit Scripting(QObject *parent = 0);

    //NicePyConsole *console;
    PythonQtScriptingConsole *console;

    ColorDecorator *colorDecorator;
    SkeletonDecorator *skeletonDecorator;
    TreeListDecorator *treeListDecorator;
    NodeListDecorator *nodeListDecorator;
    SegmentListDecorator *segmentListDecorator;

    Highlighter *highlighter;

    void run();
signals:
    
public slots:
    void addScriptingObject(const QString &name, QObject *obj);
    void addDoc();
    static void reflect(QObject *obj);
};

#endif // SCRIPTING_H
