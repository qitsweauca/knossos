/*
 *  This file is a part of KNOSSOS.
 *
 *  (C) Copyright 2018
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
 *  or contact knossosteam@gmail.com
 */

#include "brainmaps.h"

#include <jwt-cpp/jwt.h>

static std::string getJwt(const std::string & email, const std::string & privateKey) {
    using namespace std::string_literals;
    return jwt::create()
        .set_payload_claim("scope", jwt::claim{"https://www.googleapis.com/auth/brainmaps"s})
        .set_type("JWS")
        //.set_key_id(sacc["private_key_id"].toString().toStdString()) // doesn’t seem to be required
        .set_issuer(email)
        //.set_subject(sacc["client_email"].toString().toStdString()) // doesn’t seem to be required
        .set_audience("https://accounts.google.com/o/oauth2/token")
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
        .sign(jwt::algorithm::rs256{"", privateKey});
}

static void updateSegToken();

#include "network.h"

#include <QByteArray>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

template<bool block>
static auto googleRequest = [](auto token, QUrl path, QByteArray payload = QByteArray{}){
    QNetworkAccessManager & qnam = Network::singleton().manager;
    QNetworkRequest request(path);
    if (!token.isEmpty()) {
        request.setRawHeader("Authorization", (QString("Bearer ") + token).toUtf8());
    }
    if (block) {
        request.setPriority(QNetworkRequest::HighPriority);
    }
    QNetworkReply * reply;
    if (payload != QByteArray{} || path.path().endsWith(":create")) {
        if (token.isEmpty()) {
            request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
        } else {
            request.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");
        }
        reply = qnam.post(request, payload);
    } else {
        reply = qnam.get(request);
    }
    QObject::connect(reply, QOverload<QNetworkReply::NetworkError>::of(&QNetworkReply::error), [](QNetworkReply::NetworkError error){
        if (error == QNetworkReply::AuthenticationRequiredError || error == QNetworkReply::ContentAccessDenied) {
            updateSegToken();
        }
    });
    if constexpr (block) {
        return blockDownloadExtractData(*reply);
    } else {
        return reply;
    }
};

static auto googleRequestAsync = googleRequest<false>;
static auto googleRequestBlocking = googleRequest<true>;

#include <QJsonDocument>

auto getBrainmapsToken = [](const QJsonDocument & sacc) {
    const auto jwt = getJwt(sacc["client_email"].toString().toStdString(), sacc["private_key"].toString().toStdString());
    const auto payload = "grant_type=" + QByteArray("urn:ietf:params:oauth:grant-type:jwt-bearer").toPercentEncoding() + "&assertion=" + QByteArray::fromStdString(jwt);
    const auto pair = googleRequestBlocking(QString{""}, QUrl{"https://accounts.google.com/o/oauth2/token"}, payload);
    qDebug() << QJsonDocument::fromJson(pair.second);
    return std::pair<bool, QString>{pair.first, QJsonDocument::fromJson(pair.second)["access_token"].toString()};
};

#include "dataset.h"

void updateToken(Dataset & layer) {
    auto pair = getBrainmapsToken(layer.brainmapsSacc);
    if (pair.first) {
        qDebug() << "updateToken" << layer.url;
        layer.token = pair.second;
    } else {
        qDebug() << "getBrainmapsToken failed";
        throw std::runtime_error("couldn’t fetch brainmaps token");
    }
}

#include "segmentation/segmentation.h"

static void updateSegToken() {
    updateToken(Dataset::datasets[Segmentation::singleton().layerId]);
}

void createChangeStack(const Dataset & layer) {
    if (!layer.brainmapsChangeStack.isEmpty()) {
        auto url = layer.url;
        url.setPath(url.path().replace("volumes", "changes") + "/" + layer.brainmapsChangeStack + ":create");
        qDebug() << "changes.create" << layer.brainmapsChangeStack << googleRequestBlocking(layer.token, url);
    }
}

#include <QFileInfo>
#include <QJsonArray>
#include <QJsonObject>

void parseGoogleJson(Dataset & info) {
    qDebug() << "meshes" << googleRequestBlocking(info.token, info.url.toString().replace("volumes", "objects") + "/meshes").second.data();

    const auto config = googleRequestBlocking(info.token, info.url);

    if (!config.first) {
        qWarning() << "couldn’t fetch brainmaps config";
        return;
    }

    info.experimentname = QFileInfo{info.url.path()}.fileName().section(':', 2);
    const auto jmap = QJsonDocument::fromJson(config.second).object();

    const auto boundary_json = jmap["geometry"][0]["volumeSize"];
    info.boundary = {
        boundary_json["x"].toString().toInt(),
        boundary_json["y"].toString().toInt(),
        boundary_json["z"].toString().toInt(),
    };

    for (auto scaleRef : jmap["geometry"].toArray()) {
        const auto & scale_json = scaleRef.toObject()["pixelSize"].toObject();
        info.scales.emplace_back(scale_json["x"].toDouble(1), scale_json["y"].toDouble(1), scale_json["z"].toDouble(1));
    }
    info.scale = info.scales.front();

    info.lowestAvailableMag = 1;
    info.magnification = info.lowestAvailableMag;
    info.highestAvailableMag = std::pow(2,(jmap["geometry"].toArray().size()-1)); //highest google mag
    info.type = jmap["geometry"][0]["channelType"] == "UINT64" ? Dataset::CubeType::SEGMENTATION_SZ : Dataset::CubeType::RAW_PNG;
}

bool bminvalid(const bool erase, const std::uint64_t srcSvx, const std::uint64_t dstSvx) {
    const auto mergeUnfit = !erase && Segmentation::singleton().isSubObjectIdSelected(dstSvx);
    const auto splitUnfit = erase && (srcSvx == dstSvx || !Segmentation::singleton().isSubObjectIdSelected(dstSvx));
    return srcSvx == Segmentation::singleton().backgroundId || dstSvx == Segmentation::singleton().backgroundId || mergeUnfit || splitUnfit;
}

struct download_data_t {
    struct mesh_data_t {
        std::vector<float> vertices;
        std::vector<std::uint32_t> indices;
        std::size_t index_offset{0};
    };
    std::unordered_map<std::uint64_t, mesh_data_t> mesh_data;
    std::unordered_set<QNetworkReply*> replies;
    std::ptrdiff_t size{0};
};
using download_list = std::unordered_map<std::uint64_t, download_data_t>;

#include <QDataStream>
#include <QNetworkReply>

static auto parseBinaryMesh = [](QNetworkReply & reply, auto & meshdata){
    if (reply.error() != QNetworkReply::NoError) {
        qDebug() << reply.error() << reply.errorString() << reply.readAll().constData();
        return;
    }
    QDataStream ds(reply.readAll());
    ds.setByteOrder(QDataStream::LittleEndian);
    ds.setFloatingPointPrecision(QDataStream::FloatingPointPrecision::SinglePrecision);
    while (!ds.atEnd()) {
        std::uint32_t soid, verts, idx, dummy;
        ds >> soid >> dummy;
        auto fragkeys = soid;
        while (soid == fragkeys) {
            ds >> fragkeys >> dummy;
        }
        for (std::size_t i{0}; i < fragkeys; ++i) {
            quint8 frag;
            ds >> frag;
        }
        ds >> verts >> dummy >> idx >> dummy;
        auto & vertices = meshdata[soid].vertices;
        auto & indices = meshdata[soid].indices;
        auto & index_offset = meshdata[soid].index_offset;
        vertices.reserve(vertices.size() + verts);
        indices.reserve(indices.size() + idx);
        for (std::size_t i{0}; i < verts; ++i) {
            float x, y, z;
            ds >> x >> y >> z;
            vertices.push_back(x);
            vertices.push_back(y);
            vertices.push_back(z);
        }
        for (std::size_t i{0}; i < idx; ++i) {
            std::uint32_t idx, idy, idz;
            ds >> idx >> idy >> idz;
            indices.push_back(idx + index_offset);
            indices.push_back(idy + index_offset);
            indices.push_back(idz + index_offset);
        }
        index_offset = vertices.size() / 3;
    }
};

#include "skeleton/skeletonizer.h"

#include <QProgressBar>

static void updateAnnotation(download_list & download_data, QElapsedTimer & timer, std::uint64_t soid, QProgressBar & downloadProgress, QProgressBar & addProgress) {
    qDebug() << "mesh" << soid << "fetch" << download_data[soid].size/1e6 << "MB in" << timer.elapsed() << "ms";
    addProgress.setMaximum(download_data[soid].mesh_data.size());
    addProgress.setValue(0);
    addProgress.show();
    for (auto && pair : download_data[soid].mesh_data) {
        addProgress.setValue(addProgress.value() + 1);
        QVector<float> normals;
        QVector<std::uint8_t> colors;
        if (pair.second.vertices.size() < (1<<29) && pair.second.indices.size() < (1<<29)) {
            auto verts = QVector<float>(std::cbegin(pair.second.vertices), std::cend(pair.second.vertices));
            auto idc = QVector<std::uint32_t>(std::cbegin(pair.second.indices), std::cend(pair.second.indices));
            Skeletonizer::singleton().addMeshToTree(pair.first, verts, normals, idc, colors);
        } else {
            qWarning() << pair.first << ": mesh too big";
        }
    }
    qDebug() << "mesh" << soid << "add in" << timer.restart() << "ms";

    download_data.erase(soid);
    if (download_data.empty()) {
        QTimer::singleShot(450, [&download_data, &downloadProgress, &addProgress](){
            downloadProgress.setVisible(!download_data.empty());
            addProgress.hide();
        });
    }
}

template<bool isDirectConnectivity>
static QNetworkReply * fragmentListRequest(const Dataset & dataset, const std::uint64_t soid) {
    auto url = dataset.url.toString().replace("volumes", "objects")
        + QString("/meshes/%1:listfragments?objectId=%2&returnSupervoxelIds=true")
        .arg(dataset.brainmapsMeshKey).arg(soid);
    if (!dataset.brainmapsChangeStack.isEmpty() && !isDirectConnectivity) {
        url += QString{"&header.changeStackId=%1"}.arg(dataset.brainmapsChangeStack);
    }
    qDebug() << "request fragments for" << soid;
    return googleRequestAsync(dataset.token, url);
}

#include <QJsonArray>
#include <QJsonObject>

#include "stateInfo.h"
#include "widgets/mainwindow.h" // enabled + progress

static boost::optional<std::uint64_t> brainmapsDownload{boost::none};
static bool brainmapsUnfinished;

template<bool isDirectConnectivity>
void fetchFragmentsSwitch(const Dataset & dataset, const std::uint64_t soid, QElapsedTimer & timer, const int assert) {
    auto * reply = fragmentListRequest<isDirectConnectivity>(dataset, soid);
    QObject::connect(reply, &QNetworkReply::finished, [reply, timer, soid, &dataset, assert, &downloadProgress = state->mainWindow->meshDownloadProgressBar, &addProgress = state->mainWindow->meshAddProgressBar]() mutable {
        const auto data = reply->readAll();
        auto fragidsv = QJsonDocument::fromJson(data).object()["fragmentKey"].toArray().toVariantList();
        auto soidsv = QJsonDocument::fromJson(data).object()["supervoxelId"].toArray().toVariantList();
        qDebug() << "received" << fragidsv.size() << "fragements for" << soid << reply->error()
                 << (reply->error() != QNetworkReply::NoError ? reply->errorString().toUtf8().constData() : "in") << timer.elapsed() << "ms";
        // create mergelist and trees
        auto & seg = Segmentation::singleton();
        QSignalBlocker bs{seg};
        if (!isDirectConnectivity) {
            if (brainmapsDownload && brainmapsDownload.get() == soid) {
                brainmapsDownload = boost::none;
            }
            QSet<quint64> prevIds;
            if (assert && seg.hasObjects()) {
                for (const auto & so : seg.objects.front().subobjects) {
                    prevIds.insert(so.get().id);
                }
            }
            const auto bak = Segmentation::singleton().hovered_subobject_id;// drag
            seg.mergelistClear();
            Segmentation::singleton().hovered_subobject_id = bak;
            auto & obj = seg.hasObjects() ? seg.objects.front() : seg.createObject();
            seg.unselectObject(obj);
            obj.immutable = true;
            QSet<quint64> uniqueIds;
            {
                QSignalBlocker bs2{Skeletonizer::singleton()};
                QSet<treeListElement*> treesToSelect;
                for (int i = 0; i < soidsv.size(); ++i) {
                    const auto soid = soidsv[i].toULongLong();
                    uniqueIds.insert(soid);
                    if (auto tree = Skeletonizer::singleton().findTreeByTreeID(soid)) {// filter out existing trees/meshes
                        treesToSelect.insert(tree);
                        fragidsv.removeAt(i);
                        soidsv.removeAt(i);
                        --i;
                    }
                }
                for (const auto soid : uniqueIds) {
                    if (!seg.subobjectExists(soid)) {
                        seg.newSubObject(obj, soid);
                    }
                    if (auto tree = Skeletonizer::singleton().findTreeByTreeID(soid); tree == nullptr) {
                        treesToSelect.insert(&Skeletonizer::singleton().addTree(soid));
                    }
                }
                for (auto & elem : Skeletonizer::singleton().skeletonState.selectedTrees) {
                    elem->selected = false;
                }
                Skeletonizer::singleton().skeletonState.selectedTrees.clear();
                for (auto * tree : treesToSelect) {
                    Skeletonizer::singleton().skeletonState.selectedTrees.emplace_back(tree);
                    tree->selected = true;
                }
            }
            Skeletonizer::singleton().resetData();
            seg.selectObject(obj);
            bs.unblock();
            seg.resetData();

            if (assert && uniqueIds == prevIds) {
                qDebug() << "subobject list didn’t change –" << prevIds.size() << "vs." << uniqueIds.size() << "– requesting again, " << assert << " tries remaining";
                retrieveMeshes(soid, assert - 1);
                return;
            }
        }

        static download_list download_data;
        if (!fragidsv.empty()) {
            const auto chunk_size = std::max(1, std::min(256, fragidsv.size() / 6));
            for (int c = 0; c < fragidsv.size(); c += chunk_size) {
                QJsonObject request;
                QJsonArray batches;
                for (int i = c; i < std::min(c + chunk_size, fragidsv.size()); ++i) {
                    QJsonObject frags;
                    frags["objectId"] = soidsv[i].toString();
                    frags["fragmentKeys"] = fragidsv[i].toString();
                    batches.append(frags);
                }
                request["volumeId"] = dataset.url.toString().section('/', 5, 5);
                request["meshName"] = dataset.brainmapsMeshKey;
                request["batches"] = batches;

                auto * reply = googleRequestAsync(dataset.token, QUrl{"https://brainmaps.googleapis.com/v1/objects/meshes:batch"}, QJsonDocument{request}.toJson());
                download_data[soid].replies.emplace(reply);

                downloadProgress.setMaximum(downloadProgress.maximum() + 1);
                downloadProgress.show();

                QObject::connect(reply, &QNetworkReply::finished, [reply, timer, soid, &downloadProgress, &addProgress]() mutable {
                    downloadProgress.setValue(downloadProgress.value() + 1);
                    if (downloadProgress.value() == downloadProgress.maximum()) {
                        downloadProgress.setValue(0);
                        downloadProgress.setMaximum(0);
                    }

                    download_data[soid].size += reply->size();
                    parseBinaryMesh(*reply, download_data[soid].mesh_data);

                    download_data[soid].replies.erase(reply);
                    if (download_data[soid].replies.empty()) {
                        updateAnnotation(download_data, timer, soid, downloadProgress, addProgress);
                        brainmapsUnfinished = false;
                    }

                    reply->deleteLater();
                });
            }
        }
        reply->deleteLater();
    });
}

static auto fetchFragments = fetchFragmentsSwitch<false>;

void fetchDCFragments(const Dataset & dataset, const std::uint64_t soid) {
    static QElapsedTimer timer;
    timer.start();

    auto * const reply = googleRequestAsync(dataset.token, dataset.url.toString().replace("volumes", "changes") + QString{"/%1/equivalences:list"}.arg(dataset.brainmapsChangeStack), QString{R"json({"segmentId": ["%1"]})json"}.arg(soid).toUtf8());
    QObject::connect(reply, &QNetworkReply::finished, [reply, soid, dataset](){
        const auto edgeJson = QJsonDocument::fromJson(reply->readAll());
        QSet<quint64> ids;
        for (const auto edge : edgeJson["edge"].toArray()) {
            ids.insert(edge.toObject()["first"].toString().toULongLong());
            ids.insert(edge.toObject()["second"].toString().toULongLong());
        }
        if (ids.empty()) {
            ids.insert(soid);
        }
        qDebug() << "list" << /*edgeJson << ids << */ids.size();
        auto & seg = Segmentation::singleton();

        QSignalBlocker bs{seg};
        const auto bak = Segmentation::singleton().hovered_subobject_id;// drag
        seg.mergelistClear();
        Segmentation::singleton().hovered_subobject_id = bak;
        auto & obj = seg.createObject();
        seg.unselectObject(obj);
        obj.immutable = true;
        {
            QSignalBlocker bs2{Skeletonizer::singleton()};
            for (auto & elem : Skeletonizer::singleton().skeletonState.selectedTrees) {
                elem->selected = false;
            }
            Skeletonizer::singleton().skeletonState.selectedTrees.clear();
            for (const auto soid : ids) {
                if (!seg.subobjectExists(soid)) {
                    seg.newSubObject(obj, soid);
                }
                auto tree = Skeletonizer::singleton().findTreeByTreeID(soid);
                if (tree == nullptr) {
                    tree = &Skeletonizer::singleton().addTree(soid);
                    fetchFragmentsSwitch<true>(dataset, soid, timer, 0);
                }
                Skeletonizer::singleton().skeletonState.selectedTrees.emplace_back(tree);
                tree->selected = true;
            }
        }
        Skeletonizer::singleton().resetData();
        seg.selectObject(obj);
        bs.unblock();
        seg.resetData();

        if (brainmapsDownload && brainmapsDownload.get() == soid) {
            brainmapsDownload = boost::none;
        }
    });
}

#include "viewer.h" // reslice_notify

void retrieveMeshes(const std::uint64_t soid, const int assert) {
    QElapsedTimer timer;
    timer.start();

    brainmapsDownload = soid;
    state->viewer->reslice_notify(Segmentation::singleton().layerId);
    const auto & dataset = Dataset::datasets[Segmentation::singleton().layerId];
    if (Annotation::singleton().annotationMode.testFlag(AnnotationMode::SubObjectSplit)) {
        fetchDCFragments(dataset, soid);
    } else {
        fetchFragments(dataset, soid, timer, assert);
    }
}

#include <QApplication>
#include <QProgressDialog>

void bmmergesplit(const std::uint64_t src_soid, const std::uint64_t dst_soid) {
    const auto shift = Annotation::singleton().annotationMode.testFlag(AnnotationMode::SubObjectSplit);
    if (bminvalid(shift, src_soid, dst_soid)) {
        return;
    }
    auto * focusedWidget = qApp->focusWidget(); // vp loses focus on mainwindow disable, bad for space key
    state->mainWindow->setEnabled(false);
    QEventLoop pause;
    auto wait = [&pause](){
        while (brainmapsDownload) {
            QTimer::singleShot(1, [&pause](){
                pause.exit();
            });
            pause.exec();
        }
    };
    wait();
    Annotation::singleton().annotationMode.setFlag(AnnotationMode::ObjectMerge, false);
    Annotation::singleton().annotationMode.setFlag(AnnotationMode::SubObjectSplit, false);
    if (shift) {// retrieve prior cc merge list first
        retrieveMeshes(src_soid);
        wait();
    }
    if (bminvalid(shift, src_soid, dst_soid)) {
        state->mainWindow->setEnabled(true);
        return;
    }
    brainmapsDownload = src_soid;// try to keep showing yellow

    QElapsedTimer time;
    time.start();
    QPair<bool, QByteArray> pair;
    QProgressDialog progress{"Waiting for the Google server to process the request correctly", "give up", 0, 0};
    //progress.setMinimumDuration(500);
    //progress.setModal(true);
    for (int retry{10}; retry > 0; --retry) {
        const auto & dataset = Dataset::datasets[Segmentation::singleton().layerId];
        const auto url = dataset.url.toString().replace("volumes", "changes") + QString("/%1/equivalences:%2")
                .arg(dataset.brainmapsChangeStack).arg(shift ? "delete" : "set");
        const auto payload = QString{R"json({"edge": {"first": %1, "second": %2}%9})json"}.arg(src_soid).arg(dst_soid)
                .arg(shift ? "" : R"json(,"allowEquivalencesToBackground": false)json").toUtf8();
        qDebug() << url << payload;
        QElapsedTimer time;
        time.start();
        pair = googleRequestBlocking(dataset.token, url, payload);
        qDebug() << pair.first << time.nsecsElapsed()/1e9;
        if (pair.first || progress.wasCanceled()) {
            break;
        }
        if (!pair.first) {
            QTimer::singleShot(5, [&pause](){
                pause.exit();
            });
            pause.exec();
        }
    }
    state->mainWindow->setEnabled(true);
    state->mainWindow->activateWindow(); // can’t focus if window not active
    focusedWidget->setFocus();
    if (!pair.first) {
        QMessageBox box{QApplication::activeWindow()};
        box.setIcon(QMessageBox::Warning);
        box.setText(QObject::tr("Failed to upload changes."));
        box.setInformativeText(QObject::tr("They may have still been applied, but the server only responded with errors."));
        box.setDetailedText(pair.second.data());
        box.exec();
        qDebug() << box.text() << box.informativeText() << pair.second.data();
    } else {
        qDebug() << "equivalences" << pair.second.data() << time.nsecsElapsed()/1e9 << "s";
        retrieveMeshes(src_soid, 20);
    }
}

Segmentation::color_t Segmentation::brainmapsColor(const std::uint64_t subobjectId, const bool selected) const {
    Segmentation::color_t color;
    if (brainmapsDownload) {// busy
        color = std::make_tuple(255, 255, 0, Segmentation::singleton().alpha);
    } else if (Annotation::singleton().annotationMode.testFlag(AnnotationMode::SubObjectSplit)) {
        color = Segmentation::singleton().subobjectColor(subobjectId);
        if (subobjectId == Segmentation::singleton().splitId) {
            color = std::make_tuple(255, 0, 0, Segmentation::singleton().alpha);// red
        }
    } else {
        color = std::make_tuple(0, 255, 0, Segmentation::singleton().alpha);// green
    }
    if (Annotation::singleton().annotationMode.testFlag(AnnotationMode::ObjectMerge)) {
        if (!selected) {
            color = Segmentation::singleton().colorObjectFromSubobjectId(subobjectId);
        }
    } else if (!selected) {
        color = {};
    }
    return color;
}

#include <unordered_set>

std::unordered_set<std::uint64_t> split0ids;
std::unordered_set<std::uint64_t> split1ids;

QColor brainmapsMeshColor(const decltype(treeListElement::treeID) treeID) {
    if (split0ids.find(treeID) != std::end(split0ids)) {
        return Qt::blue;
    }
    if (split1ids.find(treeID) != std::end(split0ids)) {
        return Qt::darkMagenta;
    }
    QColor color;
    auto objColor = Segmentation::singleton().colorOfSelectedObject();
    if (Annotation::singleton().annotationMode.testFlag(AnnotationMode::SubObjectSplit)) {
        objColor = Segmentation::singleton().subobjectColor(treeID);
    }
    color = std::apply(static_cast<QColor(*)(int,int,int,int)>(QColor::fromRgb), objColor);
    color = QColor::fromRgb(std::get<0>(objColor), std::get<1>(objColor), std::get<2>(objColor));// skip seg alpha
    if (!Annotation::singleton().annotationMode.testFlag(AnnotationMode::SubObjectSplit)) {
        color = Qt::green;
    } else if (treeID == Segmentation::singleton().splitId) {
        color = Qt::red;
    }
    const bool meshing = state->mainWindow->meshDownloadProgressBar.value() != state->mainWindow->meshDownloadProgressBar.maximum() || state->mainWindow->meshAddProgressBar.value() != state->mainWindow->meshAddProgressBar.maximum();
    if (brainmapsDownload || meshing) {// busy
        color =  Qt::yellow;
    }
    return color;
}

void brainmapsBranchPoint(const boost::optional<nodeListElement &> node, std::uint64_t subobjID, const Coordinate & globalCoord) {
    nodeListElement * pushBranchNode = nullptr;
    if (node) {
        pushBranchNode = &node.get();
    } else {
        if (auto * tree = Skeletonizer::singleton().findTreeByTreeID(subobjID); tree && tree->selected) {
            pushBranchNode = &Skeletonizer::singleton().addNode(boost::none, 20, tree->treeID, globalCoord, ViewportType::VIEWPORT_UNDEFINED, -1, boost::none, false, {}).get();
            state->skeletonState->activeTree = tree;
            state->skeletonState->activeNode = pushBranchNode;
        }
    }
    if (pushBranchNode) {
        Skeletonizer::singleton().pushBranchNode(*pushBranchNode);
    }
}

Coordinate p0, p1;
std::uint64_t soid{};

void setSplit(const Coordinate & p, const std::uint64_t id) {
    p1 = p0;// shift
    p0 = p;
    soid = id;
}

void splitMe() {
    if (soid == Segmentation::singleton().backgroundId) {
        return;
    }
    Annotation::singleton().clearAnnotation();
    brainmapsUnfinished = true;
    retrieveMeshes(soid);
    state->mainWindow->setEnabled(false);
    QEventLoop pause;
    [&pause](){
        while (brainmapsUnfinished) {
            QTimer::singleShot(1, [&pause](){
                pause.exit();
            });
            pause.exec();
        }
    }();
    state->mainWindow->setEnabled(true);

    const auto dataset = Dataset::datasets[Segmentation::singleton().layerId];
    {
//    POST https://brainmaps.googleapis.com/v1/changes/{header.volumeId}/{header.changeStackId}/equivalences:getgroups
    const auto pair = googleRequestBlocking(dataset.token, dataset.url.toString().replace("volumes", "changes")
                                               + QString{"/%1/equivalences:getgroups"}.arg(dataset.brainmapsChangeStack),
                                               QString{R"json({"segmentId": ["%1"]})json"}.arg(soid).toUtf8());
    if (!pair.first) {
        throw std::runtime_error("getgroups fail");
    }
    const auto json{QJsonDocument::fromJson({pair.second})};
    const auto group{json["groups"][0]["groupMembers"]};
    qDebug() << group.toArray().size()/* << group*/;
    QJsonObject o;
    o["segmentId"] = group;
    {
    const auto pair = googleRequestBlocking(dataset.token, dataset.url.toString().replace("volumes", "changes")
                                            + QString{"/%1/equivalences:list"}.arg(dataset.brainmapsChangeStack),
                                            QJsonDocument{o}.toJson());
    if (!pair.first) {
        throw std::runtime_error("list fail");
    }
    for (auto edge : QJsonDocument::fromJson({pair.second})["edge"].toArray()) {
        const auto n0id = edge.toObject()["first"].toString().toULongLong();
        const auto n1id = edge.toObject()["second"].toString().toULongLong();
        auto x = [&dataset](auto nid){
            auto n = Skeletonizer::singleton().findNodeByNodeID(nid);
            if (!n) {
                const auto * tree = Skeletonizer::singleton().findTreeByTreeID(nid);
                auto pos = floatCoordinate{};
                tree->mesh->position_buf.bind();
                tree->mesh->position_buf.read(0, &pos, 3 * sizeof(float));
                tree->mesh->position_buf.release();
                pos /= dataset.scales[0];
                return &Skeletonizer::singleton().addNode(nid, pos, *tree).get();
            }
            return n;
        };
        Skeletonizer::singleton().addSegment(*x(n0id), *x(n1id));
    }
    Skeletonizer::singleton().setActiveTreeByID(soid);

    auto findNearbyNodeOfTreeByVertex = [&dataset](Coordinate ref) -> nodeListElement & {
        Coordinate min;
        treeListElement * minTree;
        for (auto & tree : state->skeletonState->trees) {
            tree.mesh->position_buf.bind();
            QVector<floatCoordinate> vertices(tree.mesh->vertex_count);
            tree.mesh->position_buf.read(0, vertices.data(), tree.mesh->position_buf.size());
            tree.mesh->position_buf.release();
            for (auto pos : vertices) {
                pos /= dataset.scales[0];
                if ((ref - pos).length() < (ref - min).length()) {
                    min = pos;
                    minTree = &tree;
                }
            }
        }
        return *Skeletonizer::singleton().findNearbyNode(minTree, ref);
    };

    std::vector<nodeListElement *> shortestPathV(nodeListElement & lhs, const nodeListElement & rhs);
    auto path = shortestPathV(findNearbyNodeOfTreeByVertex(p0), findNearbyNodeOfTreeByVertex(p1));
    split0ids.clear();
    split1ids.clear();
    std::size_t totalSize{0};
    for (std::size_t i{0}; i < path.size(); ++i) {
        totalSize += path[i]->correspondingTree->mesh->vertex_count;
    }
    std::size_t rollingSize{0}, min{totalSize};
    bool done{false};
    for (std::size_t i{0}; i < path.size(); ++i) {
        const auto inc{path[i]->correspondingTree->mesh->vertex_count};
        const auto diff{std::abs(static_cast<std::ptrdiff_t>((rollingSize + inc) - totalSize/2))};
        if (!done && diff < min) {// getting closer to our splitting point
            rollingSize += inc;
            min = diff;
            split0ids.insert(path[i]->correspondingTree->treeID);
        } else {
            done = true;
            split1ids.insert(path[i]->correspondingTree->treeID);
        }
    }
    qDebug() << rollingSize << totalSize << min << split0ids.size() << split1ids.size();
    while (!state->skeletonState->nodesByNodeID.empty()) {
        Skeletonizer::singleton().delNode(0, std::begin(state->skeletonState->nodesByNodeID)->second);
    }
    std::vector<treeListElement *> trees;
    for (auto & tree : state->skeletonState->trees) {
        trees.emplace_back(&tree);
    }
    Skeletonizer::singleton().selectTrees(trees);
    }
    }
}
