#ifndef SKELETONIZER_H
#define SKELETONIZER_H

/*
 *  This file is a part of KNOSSOS.
 *
 *  (C) Copyright 2007-2013
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
 */

/*
 * For further information, visit http://www.knossostool.org or contact
 *     Joergen.Kornfeld@mpimf-heidelberg.mpg.de or
 *     Fabian.Svara@mpimf-heidelberg.mpg.de
 */

#include "skeleton/tree.h"
#include "widgets/viewport.h"

#include <QObject>
#include <QSet>
#include <QVariantHash>

#include <boost/optional.hpp>

#include <memory>
#include <unordered_map>
#include <version.h>

class nodeListElement;
class segmentListElement;
class commentListElement;

// skeleton vp orientation
#define SKELVP_XY_VIEW 0
#define SKELVP_XZ_VIEW 1
#define SKELVP_YZ_VIEW 2
#define SKELVP_R90 3
#define SKELVP_R180 4
#define SKELVP_RESET 5

struct SkeletonState {
    treeListElement * activeTree{nullptr};
    nodeListElement * activeNode{nullptr};

    std::list<treeListElement> trees;
    std::unordered_map<int, treeListElement *> treesByID;
    std::unordered_map<uint, nodeListElement *> nodesByNodeID;
    int treeElements{0};
    int totalNodeElements{0};
    int greatestTreeID{0};
    std::uint64_t greatestNodeID{0};

    std::vector<treeListElement *> selectedTrees;
    std::vector<nodeListElement *> selectedNodes;

    std::vector<std::uint64_t> branchStack;
    bool branchpointUnresolved{false};

    commentListElement * currentComment{nullptr};
    QString commentBuffer;
    uint totalComments{0};

    QString nodeCommentFilter;
    QString treeCommentFilter;

    float defaultNodeRadius{1.5f};

    bool lockPositions{false};
    bool positionLocked{false};
    QString onCommentLock{"seed"};
    Coordinate lockedPosition;
    long unsigned int lockRadius{100};

    float rotdx;
    float rotdy;
    int rotationcounter;
    // Stores the angles of the cube in the SkeletonVP
    float rotationState[16];

    float translateX;
    float translateY;

    int definedSkeletonVpView{SKELVP_RESET};

    // Stores the model view matrix for user performed VP rotations.
    float skeletonVpModelView[16];
    // Current zoom level. 0: no zoom; near 1: maximum zoom.
    double zoomLevel;
    //boundary of the visualized volume in the skeleton viewport
    int volBoundary{2 * std::max({state->boundary.x, state->boundary.y, state->boundary.z})};

    QString skeletonCreatedInVersion{KVERSION};
    QString skeletonLastSavedInVersion;

    //If true, loadSkeleton merges the current skeleton with the provided
    bool mergeOnLoadFlag;
};

class Skeletonizer : public QObject {
    Q_OBJECT
    QSet<QString> textProperties;
    QSet<QString> numberProperties;

public:
    template<typename T>
    void select(QSet<T*>);
    void setActive(nodeListElement & elem);
    void setActive(treeListElement & elem);
    template<typename T>
    void toggleSelection(const QSet<T*> & nodes);
    template<typename Elem>
    void notifySelection();
    std::vector<nodeListElement*> nodesOrdered;
    std::vector<treeListElement*> treesOrdered;

    SkeletonState skeletonState;
    Skeletonizer() {
        state->skeletonState = &skeletonState;
    }
    static Skeletonizer & singleton() {
        static Skeletonizer skeletonizer;
        return skeletonizer;
    }

    template<typename Func>
    treeListElement * getTreeWithRelationalID(treeListElement * currentTree, Func func);
    treeListElement * getTreeWithPrevID(treeListElement * currentTree);
    treeListElement * getTreeWithNextID(treeListElement * currentTree);

    template<typename Func>
    nodeListElement * getNodeWithRelationalID(nodeListElement * currentNode, bool sameTree, Func func);
    nodeListElement * getNodeWithPrevID(nodeListElement * currentNode, bool sameTree);
    nodeListElement * getNodeWithNextID(nodeListElement * currentNode, bool sameTree);
    nodeListElement * findNearbyNode(treeListElement * nearbyTree, Coordinate searchPosition);

    QList<treeListElement *> findTreesContainingComment(const QString &comment);

signals:
    void branchPoppedSignal();
    void branchPushedSignal();
    void nodeAddedSignal(const nodeListElement & node);
    void nodeChangedSignal(const nodeListElement & node);
    void nodeRemovedSignal(const uint nodeID);
    void propertiesChanged(const QSet<QString> & numberProperties);
    void treeAddedSignal(const treeListElement & tree);
    void treeChangedSignal(const treeListElement & tree);
    void treeRemovedSignal(const int treeID);
    void treesMerged(const int treeID,const int treeID2);
    void nodeSelectionChangedSignal();
    void treeSelectionChangedSignal();
    void resetData();
public slots:
    uint64_t findAvailableNodeID();
    boost::optional<nodeListElement &> addNode(uint64_t nodeID, const float radius, const int treeID, const Coordinate & position, const ViewportType VPtype, const int inMag, boost::optional<uint64_t> time, const bool respectLocks, const QHash<QString, QVariant> & properties = {});

    void selectNodes(QSet<nodeListElement *> nodes);
    void toggleNodeSelection(const QSet<nodeListElement *> & nodes);
    void selectTrees(const std::vector<treeListElement*> & trees);
    void deleteSelectedTrees();
    void deleteSelectedNodes();
    void toggleConnectionOfFirstPairOfSelectedNodes(QWidget * const parent);

    bool delTree(int treeID);
    void clearSkeleton();
    boost::optional<nodeListElement &> UI_addSkeletonNode(const Coordinate & clickedCoordinate, ViewportType VPtype);
    bool setActiveNode(nodeListElement *node);
    bool addTreeCommentToSelectedTrees(QString comment);
    bool addTreeComment(int treeID, QString comment);
    static bool unlockPosition();
    static bool lockPosition(Coordinate lockCoordinate);
    commentListElement *nextComment(QString searchString);
    commentListElement *previousComment(QString searchString);
    bool editNode(uint nodeID, nodeListElement *node, float newRadius, const Coordinate & newPos, int inMag);
    bool delNode(uint nodeID, nodeListElement *nodeToDel);
    bool addComment(QString content, nodeListElement &node);
    bool editComment(commentListElement *currentComment, uint nodeID, QString newContent, nodeListElement *newNode, uint newNodeID);
    void setComment(nodeListElement & commentNode, const QString & newContent);
    bool setComment(QString newContent, nodeListElement *commentNode, uint commentNodeID);
    bool delComment(commentListElement *currentComment, uint commentNodeID);
    void setSubobject(nodeListElement & node, const quint64 subobjectId);
    void setSubobjectSelectAndMergeWithPrevious(nodeListElement & node, const quint64 subobjectId, nodeListElement * previousNode);
    void updateSubobjectCountFromProperty(nodeListElement & node);
    void unsetSubobjectOfHybridNode(nodeListElement & node);
    void movedHybridNode(nodeListElement & node, const quint64 newSubobjectId, const Coordinate & oldPos);
    void selectObjectForNode(const nodeListElement & node);
    void jumpToNode(const nodeListElement & node);
    bool setActiveTreeByID(int treeID);

    bool loadXmlSkeleton(QIODevice &file, const QString & treeCmtOnMultiLoad = "");
    bool saveXmlSkeleton(QIODevice &file) const;

    nodeListElement *popBranchNodeAfterConfirmation(QWidget * const parent);
    nodeListElement *popBranchNode();
    void pushBranchNode(nodeListElement & branchNode);
    bool moveToNextTree();
    bool moveToPrevTree();
    bool moveToPrevNode();
    bool moveToNextNode();
    bool moveSelectedNodesToTree(int treeID);
    static treeListElement* findTreeByTreeID(int treeID);
    static nodeListElement *findNodeByNodeID(uint nodeID);
    static QList<nodeListElement *> findNodesInTree(treeListElement & tree, const QString & comment);
    bool addSegment(nodeListElement &sourceNodeID, nodeListElement &targetNodeID);
    bool delSegment(std::list<segmentListElement>::iterator segToDelIt);
    void toggleLink(nodeListElement & lhs, nodeListElement & rhs);
    void restoreDefaultTreeColor(treeListElement & tree);

    bool extractConnectedComponent(int nodeID);
    int findAvailableTreeID();
    treeListElement * addTreeListElement();
    treeListElement * addTreeListElement(int treeID, color4F color = {-1, -1, -1, 1});
    bool mergeTrees(int treeID1, int treeID2);
    void updateTreeColors();
    static std::list<segmentListElement>::iterator findSegmentBetween(nodeListElement & sourceNode, const nodeListElement & targetNode);
    boost::optional<nodeListElement &> addSkeletonNodeAndLinkWithActive(const Coordinate & clickedCoordinate, ViewportType VPtype, int makeNodeActive);

    bool searchInComment(char *searchString, commentListElement *comment);
    static bool updateCircRadius(nodeListElement *node);

public:
    bool areConnected(const nodeListElement & v,const nodeListElement & w) const; // true if a path between the two nodes can be found.
    float radius(const nodeListElement &node) const;
    float segmentSizeAt(const nodeListElement &node) const;
    const QSet<QString> getNumberProperties() const { return numberProperties; }
};

#endif // SKELETONIZER_H
