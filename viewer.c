/*
 *  This file is a part of KNOSSOS.
 *
 *  (C) Copyright 2007-2012
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

/*
 *  This file contains functions that are called by the thread (entry point: fct viewer()) managing the GUI,
 *  all openGL rendering operations, all user interactions (event handling in general) and
 *  all skeletonization operations commanded directly by the user over the GUI. The files gui.c, renderer.c and
 *  skeletonizer.c contain functions mainly used by the corresponding "subsystems". viewer.c contains the main
 *  event loop and routines that handle (extract slices, pack into openGL textures,...) the data coming
 *  from the loader thread.
*/

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <SDL/SDL.h>
#include <GL/gl.h>
#include <GL/glu.h>

#include <agar/core.h>
#include <agar/gui.h>
#include <agar/gui/cursors.h>

#include "customCursor.xpm"
#include "knossos-global.h"
#include "viewer.h"

extern struct stateInfo *tempConfig;
extern struct stateInfo *state;

int viewer() {
    SDL_Event event;

    struct viewerState *viewerState = state->viewerState;
    struct vpList *viewPorts = NULL;
    struct vpListElement *currentVp = NULL, *nextVp = NULL;
    uint32_t drawCounter = 0;
    SDL_Cursor *customCursor = NULL;

    /* init the viewer thread and all subsystems handled by it */
    if(initViewer(state) == FALSE) {
        LOG("Error initializing the viewer.");
        return FALSE;
    }

    /* Event and rendering loop.
     * What happens is that we go through lists of pending texture parts and load
     * them if they are available. If they aren't, they are added to a backlog
     * which is processed at a later time.
     * While we are loading the textures, we check for events. Some events
     * might cancel the current loading process. When all textures / backlogs
     * have been processed, we go into an idle state, in which we wait for events.
     */

    state->viewerState->viewerReady = TRUE;

    /* We're manually calling SDL_SetCursor so the cursor will be displayed before
     * the agar event loop becomes active */
    customCursor = GenCursor(customCursorXPM, 16, 16);
    SDL_SetCursor(customCursor);
    //agDefaultCursor = customCursor; //AGAR14

    updateViewerState(state);
    recalcTextureOffsets();
    splashScreen();
    /* Display info about skeleton save path here TODO */

    while(TRUE) {
        // This creates a circular doubly linked list of
        // pending viewports (viewports for which the texture has not yet been
        // completely loaded) from the viewport-array in the viewerState
        // structure.
        // The idea is that we can easily remove the element representing a
        // pending viewport once its texture is completely loaded.
        viewPorts = vpListGenerate(viewerState);
        drawCounter = 0;

        currentVp = viewPorts->entry;
        while(viewPorts->elements > 0) {
            nextVp = currentVp->next;
            // printf("currentVp at %p, nextVp at %p.\n", currentVp, nextVp);

            // We iterate over the list and either handle the backlog (a list
            // of datacubes and associated offsets, see headers) if there is
            // one or start loading everything from scratch if there is none.

            if(currentVp->viewPort->type != VIEWPORT_SKELETON) {

                if(currentVp->backlog->elements == 0) {
                    // There is no backlog. That means we haven't yet attempted
                    // to load the texture for this viewport, which is what we
                    // do now. If we can't complete the texture because a Dc
                    // is missing, a backlog is generated.
                    vpGenerateTexture(currentVp, viewerState, state);
                } else {
                    // There is a backlog. We go through its elements
                    vpHandleBacklog(currentVp, viewerState, state);
                }

                if(currentVp->backlog->elements == 0) {
                    // There is no backlog after either handling the backlog
                    // or loading the whole texture. That means the texture is
                    // complete. We can remove the viewport/ from the list.

                       /*  XXX TODO XXX
                        The Dc2Pointer hashtable locking is currently done at pretty high
                        frequency by vpHandleBacklog() and might slow down the
                        loader.
                        We might want to introduce a locked variable that says how many
                        yet "unused" (by the viewer) cubes the loader has provided.
                        Unfortunately, we can't non-busy wait on the loader _and_
                        events, unless the loader generates events itself... So if this
                        really is a bottleneck it might be worth to think about it
                        again. */
                    vpListDelElement(viewPorts, currentVp);
                }
            }

            drawCounter++;
            if(drawCounter == 3) {
                drawCounter = 0;

                updateViewerState(state);
                recalcTextureOffsets();
                updateSkeletonState(state);
                drawGUI();

                while(SDL_PollEvent(&event)) {
                    if(handleEvent(event, state) == FALSE) {
                        state->viewerState->viewerReady = FALSE;
                        return TRUE;
                    }
                }

                if(viewerState->userMove == TRUE)
                    break;
            }

            // An incoming user movement event makes the current backlog &
            // viewport lists obsolete and we regenerate them dependant on
            // the new position

            // Leaves the loop that checks regularily for new available
            // texture parts because the whole texture has to be recreated
            // if the users moves

            currentVp = nextVp;
        }
        vpListDel(viewPorts);

        if(viewerState->userMove == FALSE) {
            if(SDL_WaitEvent(&event)) {
                if(handleEvent(event, state) != TRUE) {
                    state->viewerState->viewerReady = FALSE;
                    return TRUE;
                }
            }
        }

        viewerState->userMove = FALSE;
    }

    return TRUE;
}
static int32_t initViewer(struct stateInfo *state) {
    calcLeftUpperTexAbsPx(state);

    /* init the skeletonizer */
    if(initSkeletonizer(state) == FALSE) {
        LOG("Error initializing the skeletonizer.");
        return FALSE;
    }

    if(SDLNet_Init() == FAIL) {
        LOG("Error initializing SDLNet: %s.", SDLNet_GetError());
        return FALSE;
    }

    /* init the agar gui system */
    if(initGUI() == FALSE) {
        LOG("Error initializing the agar system / gui.");
        return FALSE;
    }

    /* Set up the clipboard */
    if(SDLScrap_Init() < 0) {
        LOG("Couldn't init clipboard: %s\n", SDL_GetError());
        _Exit(FALSE);
    }

	/*TDitem */

    /* Load the color map for the overlay */

    if(state->overlay) {
        LOG("overlayColorMap at %p\n", &(state->viewerState->overlayColorMap[0][0]));
        if(loadDatasetColorTable("stdOverlay.lut",
                          &(state->viewerState->overlayColorMap[0][0]),
                          GL_RGBA,
                          state) == FALSE) {
            LOG("Overlay color map stdOverlay.lut does not exist.");
            state->overlay = FALSE;
        }
    }

    /* This is the buffer that holds the actual texture data (for _all_ textures) */

    state->viewerState->texData =
        malloc(TEXTURE_EDGE_LEN
               * TEXTURE_EDGE_LEN
               * sizeof(Byte)
               * 3);
    if(state->viewerState->texData == NULL) {
        LOG("Out of memory.");
        _Exit(FALSE);
    }
    memset(state->viewerState->texData, '\0',
           TEXTURE_EDGE_LEN
           * TEXTURE_EDGE_LEN
           * sizeof(Byte)
           * 3);

    /* This is the buffer that holds the actual overlay texture data (for _all_ textures) */

    if(state->overlay) {
        state->viewerState->overlayData =
            malloc(TEXTURE_EDGE_LEN *
                   TEXTURE_EDGE_LEN *
                   sizeof(Byte) *
                   4);
        if(state->viewerState->overlayData == NULL) {
            LOG("Out of memory.");
            _Exit(FALSE);
        }
        memset(state->viewerState->overlayData, '\0',
               TEXTURE_EDGE_LEN
               * TEXTURE_EDGE_LEN
               * sizeof(Byte)
               * 4);
    }

    /* This is the data we use when the data for the
       slices is not yet available (hasn't yet been loaded). */

    state->viewerState->defaultTexData = malloc(TEXTURE_EDGE_LEN * TEXTURE_EDGE_LEN
                                                * sizeof(Byte)
                                                * 3);
    if(state->viewerState->defaultTexData == NULL) {
        LOG("Out of memory.");
        _Exit(FALSE);
    }
    memset(state->viewerState->defaultTexData, '\0', TEXTURE_EDGE_LEN * TEXTURE_EDGE_LEN
                                                     * sizeof(Byte)
                                                     * 3);

    /* Default data for the overlays */
    if(state->overlay) {
        state->viewerState->defaultOverlayData = malloc(TEXTURE_EDGE_LEN * TEXTURE_EDGE_LEN
                                                        * sizeof(Byte)
                                                        * 4);
        if(state->viewerState->defaultOverlayData == NULL) {
            LOG("Out of memory.");
            _Exit(FALSE);
        }
        memset(state->viewerState->defaultOverlayData, '\0', TEXTURE_EDGE_LEN * TEXTURE_EDGE_LEN
                                                             * sizeof(Byte)
                                                             * 4);
    }

    /* init the rendering system */
    if(initRenderer() == FALSE) {
        LOG("Error initializing the rendering system.")
        return FALSE;
    }

    sendLoadSignal(state->viewerState->currentPosition.x, state->viewerState->currentPosition.y,
                   state->viewerState->currentPosition.z);



    return TRUE;
}

/* TDitem */
int32_t updateViewerState(struct stateInfo *state) {
    int32_t i;

    /*if(!(state->viewerState->currentPosition.x == (tempConfig->viewerState->currentPosition.x - 1))) {
        state->viewerState->currentPosition.x = tempConfig->viewerState->currentPosition.x - 1;
    }
    if(!(state->viewerState->currentPosition.y == (tempConfig->viewerState->currentPosition.y - 1))) {
        state->viewerState->currentPosition.y = tempConfig->viewerState->currentPosition.y - 1;
    }
    if(!(state->viewerState->currentPosition.z == (tempConfig->viewerState->currentPosition.z - 1))) {
        state->viewerState->currentPosition.z = tempConfig->viewerState->currentPosition.z - 1;
    }*/

   // int32_t i = 0;

    if(state->viewerState->filterType != tempConfig->viewerState->filterType) {
        state->viewerState->filterType = tempConfig->viewerState->filterType;

        for(i = 0; i < state->viewerState->numberViewPorts; i++) {
            glBindTexture(GL_TEXTURE_2D, state->viewerState->viewPorts[i].texture.texHandle);
            // Set the parameters for the texture.
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, state->viewerState->filterType);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, state->viewerState->filterType);

            glBindTexture(GL_TEXTURE_2D, state->viewerState->viewPorts[i].texture.overlayHandle);
            // Set the parameters for the texture.
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, state->viewerState->filterType);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, state->viewerState->filterType);
        }
        glBindTexture(GL_TEXTURE_2D, 0);
    }

    updateZoomCube(state);

    if(state->viewerState->workMode != tempConfig->viewerState->workMode)
        state->viewerState->workMode = tempConfig->viewerState->workMode;

    if(state->viewerState->dropFrames != tempConfig->viewerState->dropFrames)
        state->viewerState->dropFrames = tempConfig->viewerState->dropFrames;

    if(state->viewerState->stepsPerSec != tempConfig->viewerState->stepsPerSec) {
        state->viewerState->stepsPerSec = tempConfig->viewerState->stepsPerSec;

        if(SDL_EnableKeyRepeat(200, (1000 / state->viewerState->stepsPerSec)) == FAIL)
            LOG("Error setting key repeat parameters.");
    }

    if(state->viewerState->recenteringTime != tempConfig->viewerState->recenteringTime)
        state->viewerState->recenteringTime = tempConfig->viewerState->recenteringTime;

    if(state->viewerState->recenteringTimeOrth != tempConfig->viewerState->recenteringTimeOrth)
        state->viewerState->recenteringTimeOrth = tempConfig->viewerState->recenteringTimeOrth;

    return TRUE;
}

/* This function updates state->viewerState->zoomCube after the user changed the zoom factor. */
uint32_t updateZoomCube() {
    int32_t i, residue, max, currentZoomCube, oldZoomCube;

    /* Notice int division! */
    max = ((state->M/2)*2-1);
    oldZoomCube = state->viewerState->zoomCube;
    state->viewerState->zoomCube = 0;

    for(i = 0; i < state->viewerState->numberViewPorts; i++) {
        if(state->viewerState->viewPorts[i].type != VIEWPORT_SKELETON) {
            residue = ((max*state->cubeEdgeLength)
            - ((int32_t)(state->viewerState->viewPorts[i].texture.displayedEdgeLengthX
            / state->viewerState->viewPorts[i].texture.texUnitsPerDataPx)))
            / state->cubeEdgeLength;

            if(residue%2) residue = residue / 2 + 1;
            else if((residue%2 == 0) && (residue != 0)) residue = (residue - 1) / 2 + 1;
            currentZoomCube = (state->M/2)-residue;
            if(state->viewerState->zoomCube < currentZoomCube) state->viewerState->zoomCube = currentZoomCube;

            residue = ((max*state->cubeEdgeLength)
            - ((int32_t)(state->viewerState->viewPorts[i].texture.displayedEdgeLengthY
            / state->viewerState->viewPorts[i].texture.texUnitsPerDataPx)))
            / state->cubeEdgeLength;

            if(residue%2) residue = residue / 2 + 1;
            else if((residue%2 == 0) && (residue != 0)) residue = (residue - 1) / 2 + 1;
            currentZoomCube = (state->M/2)-residue;
            if(state->viewerState->zoomCube < currentZoomCube) state->viewerState->zoomCube = currentZoomCube;
        }
    }
    if(oldZoomCube != state->viewerState->zoomCube) {
        state->skeletonState->skeletonChanged = TRUE;
    }

    return TRUE;
}

uint32_t createScreen(struct stateInfo *state) {
    // initialize window
    //SDL_GL_SetAttribute( SDL_GL_GREEN_SIZE, 5 );
    //SDL_GL_SetAttribute( SDL_GL_BLUE_SIZE, 5 );
    //SDL_GL_SetAttribute( SDL_GL_DEPTH_SIZE, 16 );

    //SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    if(state->viewerState->multisamplingOnOff) {
        //SDL_GL_SetAttribute(SDL_GL_MULTISAMPLEBUFFERS, 1);
        //SDL_GL_SetAttribute(SDL_GL_MULTISAMPLESAMPLES, 4);
    }
    //else SDL_GL_SetAttribute(SDL_GL_MULTISAMPLEBUFFERS, 0);

    /*
       At least on linux, the working directory is the directory from which
       knossos was called. So 'icon' will or will not be found depending on the
       directory from which knossos was started.
    */



    /*state->viewerState->screen = SDL_SetVideoMode(state->viewerState->screenSizeX,
                                 state->viewerState->screenSizeY, 24,
                                 SDL_OPENGL  | SDL_RESIZABLE);*/

    /*if(state->viewerState->screen == NULL) {
        printf("Unable to create screen: %s\n", SDL_GetError());
        return FALSE;
    }*/




    //set clear color (background) and clear with it


    return TRUE;
}

/*TDitem. do we really need this guy here? */
uint32_t cleanUpViewer(struct viewerState *viewerState) {
/*
    for(i = 0; i < viewerState->numberViewPorts; i++) {
        free(viewerState->viewPorts[i].texture.data);
        free(viewerState->viewPorts[i].texture.empty);
    }
    free(viewerState->viewPorts);
*/
    return TRUE;
}

static uint32_t dcSliceExtract(Byte *datacube,
                               Byte *slice,
                               size_t dcOffset,
                               struct viewPort *viewPort,
                               struct stateInfo *state) {

    datacube += dcOffset;

    if(state->viewerState->datasetAdjustmentOn) {
        /* Texture type GL_RGB and we need to adjust coloring */
        sliceExtract_adjust(datacube, slice, viewPort, state);
    }
    else {
        /* Texture type GL_RGB and we don't need to adjust anything*/
        sliceExtract_standard(datacube, slice, viewPort, state);
    }

    return TRUE;
}

static uint32_t ocSliceExtract(Byte *datacube,
                               Byte *slice,
                               size_t dcOffset,
                               struct viewPort *viewPort,
                               struct stateInfo *state) {
    int32_t i, j;
    int32_t objId,
            *objIdP;

    objIdP = &objId;

    datacube += dcOffset;

    switch(viewPort->type) {
        case SLICE_XY:
            for(i = 0; i < state->cubeSliceArea; i++) {
                memcpy(objIdP, datacube, OBJID_BYTES);
                slice[0] = state->viewerState->overlayColorMap[0][objId % 256];
                slice[1] = state->viewerState->overlayColorMap[1][objId % 256];
                slice[2] = state->viewerState->overlayColorMap[2][objId % 256];
                slice[3] = state->viewerState->overlayColorMap[3][objId % 256];

                //printf("(%d, %d, %d, %d)", slice[0], slice[1], slice[2], slice[3]);

                datacube += OBJID_BYTES;
                slice += 4;
            }

            break;

        case SLICE_XZ:
            for(j = 0; j < state->cubeEdgeLength; j++) {
                for(i = 0; i < state->cubeEdgeLength; i++) {
                    memcpy(objIdP, datacube, OBJID_BYTES);
                    slice[0] = state->viewerState->overlayColorMap[0][objId % 256];
                    slice[1] = state->viewerState->overlayColorMap[1][objId % 256];
                    slice[2] = state->viewerState->overlayColorMap[2][objId % 256];
                    slice[3] = state->viewerState->overlayColorMap[3][objId % 256];

                    datacube += OBJID_BYTES;
                    slice += 4;
                }

                datacube = datacube
                         + state->cubeSliceArea * OBJID_BYTES
                         - state->cubeEdgeLength * OBJID_BYTES;
            }

            break;

        case SLICE_YZ:
            for(i = 0; i < state->cubeSliceArea; i++) {
                memcpy(objIdP, datacube, OBJID_BYTES);
                slice[0] = state->viewerState->overlayColorMap[0][objId % 256];
                slice[1] = state->viewerState->overlayColorMap[1][objId % 256];
                slice[2] = state->viewerState->overlayColorMap[2][objId % 256];
                slice[3] = state->viewerState->overlayColorMap[3][objId % 256];

                datacube += state->cubeEdgeLength * OBJID_BYTES;
                slice += 4;
            }

            break;
    }

    return TRUE;
}

static uint32_t sliceExtract_standard(Byte *datacube,
                                      Byte *slice,
                                      struct viewPort *viewPort,
                                      struct stateInfo *state) {

    int32_t i, j;

    switch(viewPort->type) {
        case SLICE_XY:
            for(i = 0; i < state->cubeSliceArea; i++) {
                slice[0] = slice[1]
                         = slice[2]
                         = *datacube;

                datacube++;
                slice += 3;
            }

            break;

        case SLICE_XZ:
            for(j = 0; j < state->cubeEdgeLength; j++) {
                for(i = 0; i < state->cubeEdgeLength; i++) {
                    slice[0] = slice[1]
                             = slice[2]
                             = *datacube;

                    datacube++;
                    slice += 3;
                }

                datacube = datacube
                         + state->cubeSliceArea
                         - state->cubeEdgeLength;
            }

            break;

        case SLICE_YZ:
            for(i = 0; i < state->cubeSliceArea; i++) {
                slice[0] = slice[1]
                         = slice[2]
                         = *datacube;

                datacube += state->cubeEdgeLength;
                slice += 3;
            }

            break;
    }

    return TRUE;
}

static uint32_t sliceExtract_adjust(Byte *datacube,
                                    Byte *slice,
                                    struct viewPort *viewPort,
                                    struct stateInfo *state) {

    int32_t i, j;

    switch(viewPort->type) {
		case SLICE_XY:
            for(i = 0; i < state->cubeSliceArea; i++) {
                slice[0] = state->viewerState->datasetAdjustmentTable[0][*datacube];
                slice[1] = state->viewerState->datasetAdjustmentTable[1][*datacube];
                slice[2] = state->viewerState->datasetAdjustmentTable[2][*datacube];

                datacube++;
                slice += 3;
            }

            break;

        case SLICE_XZ:
            for(j = 0; j < state->cubeEdgeLength; j++) {
                for(i = 0; i < state->cubeEdgeLength; i++) {
                    slice[0] = state->viewerState->datasetAdjustmentTable[0][*datacube];
                    slice[1] = state->viewerState->datasetAdjustmentTable[1][*datacube];
                    slice[2] = state->viewerState->datasetAdjustmentTable[2][*datacube];

                    datacube++;
                    slice += 3;
                }

                datacube  = datacube
                            + state->cubeSliceArea
                            - state->cubeEdgeLength;
            }

            break;

        case SLICE_YZ:
            for(i = 0; i < state->cubeSliceArea; i++) {
                slice[0] = state->viewerState->datasetAdjustmentTable[0][*datacube];
                slice[1] = state->viewerState->datasetAdjustmentTable[1][*datacube];
                slice[2] = state->viewerState->datasetAdjustmentTable[2][*datacube];

                datacube += state->cubeEdgeLength;
                slice += 3;
            }

            break;
    }

	return TRUE;
}

static struct vpList *vpListNew() {
    struct vpList *newVpList = NULL;

    newVpList = malloc(sizeof(struct vpList));
    if(newVpList == NULL) {
        printf("Out of memory.\n");
        return NULL;
    }
    newVpList->entry = NULL;
    newVpList->elements = 0;

    return newVpList;
}

static int32_t vpListAddElement(
    struct vpList *vpList, struct viewPort *viewPort, struct vpBacklog *backlog) {
    struct vpListElement *newElement;

    newElement = malloc(sizeof(struct vpListElement));
    if(newElement == NULL) {
        LOG("Out of memory\n");
        /* Do not return FALSE here. That's a bug. FAIL is hackish... Is there a
         * better way? */
        return FAIL;
    }

    newElement->viewPort = viewPort;
    newElement->backlog = backlog;

    if(vpList->entry != NULL) {
        vpList->entry->next->previous = newElement;
        newElement->next = vpList->entry->next;
        vpList->entry->next = newElement;
        newElement->previous = vpList->entry;
    } else {
        vpList->entry = newElement;
        vpList->entry->next = newElement;
        vpList->entry->previous = newElement;
    }

    vpList->elements = vpList->elements + 1;

    return vpList->elements;
}

static struct vpList *vpListGenerate(struct viewerState *viewerState) {
    struct vpList *newVpList = NULL;
    struct vpBacklog *currentBacklog = NULL;
    int i = 0;

    newVpList = vpListNew();
    if(newVpList == NULL) {
        LOG("Error generating new vpList.");
        _Exit(FALSE);
    }

    for(i = 0; i < viewerState->numberViewPorts; i++) {
        if(viewerState->viewPorts[i].type == VIEWPORT_SKELETON)
            continue;
        currentBacklog = backlogNew();
        if(currentBacklog == NULL) {
            LOG("Error creating backlog.");
            _Exit(FALSE);
        }
        vpListAddElement(newVpList, &(viewerState->viewPorts[i]), currentBacklog);
    }

    return newVpList;
}

static int32_t vpListDelElement(struct vpList *list, struct vpListElement *element) {
    if(element->next == element) {
        // This is the only element in the list
        list->entry = NULL;
    } else {
        element->next->previous = element->previous;
        element->previous->next = element->next;
        list->entry = element->next;
    }

    if(backlogDel(element->backlog) == FALSE) {
        LOG("Error deleting backlog at %p of vpList element at %p.",
               element->backlog, element);
        return FAIL;
    }
    free(element);

    list->elements = list->elements - 1;

    return list->elements;
}

static int32_t vpListDel(struct vpList *list) {
    while(list->elements > 0) {
        if(vpListDelElement(list, list->entry) < 0) {
            LOG("Error deleting element at %p from the slot list %d elements remain in the list.",
                   list->entry, list->elements);
            return FALSE;
        }
    }

    free(list);

    return TRUE;
}

static struct vpBacklog *backlogNew() {
    struct vpBacklog *newBacklog;

    newBacklog = malloc(sizeof(struct vpBacklog));
    if(newBacklog == NULL) {
        printf("Out of memory.\n");
        return NULL;
    }
    newBacklog->entry = NULL;
    newBacklog->elements = 0;

    return newBacklog;
}

static int32_t backlogDelElement(struct vpBacklog *backlog, struct vpBacklogElement *element) {
    if(element->next == element) {
        // This is the only element in the list
        backlog->entry = NULL;
    } else {
        element->next->previous = element->previous;
        element->previous->next = element->next;
        backlog->entry = element->next;
    }

    free(element);

    backlog->elements = backlog->elements - 1;

    return backlog->elements;
}

static int32_t backlogAddElement(struct vpBacklog *backlog,
                                 Coordinate datacube,
                                 uint32_t dcOffset,
                                 Byte *slice,
                                 uint32_t x_px,
                                 uint32_t y_px,
                                 uint32_t cubeType) {

    struct vpBacklogElement *newElement;

    newElement = malloc(sizeof(struct vpBacklogElement));
    if(newElement == NULL) {
        LOG("Out of memory.");
        /* Do not return FALSE here. That's a bug. FAIL is hackish... Is there a better way? */
        return FAIL;
    }

    newElement->slice = slice;
    SET_COORDINATE(newElement->cube, datacube.x, datacube.y, datacube.z);
    newElement->x_px = x_px;
    newElement->y_px = y_px;
    newElement->dcOffset = dcOffset;
    newElement->cubeType = cubeType;

    if(backlog->entry != NULL) {
        backlog->entry->next->previous = newElement;
        newElement->next = backlog->entry->next;
        backlog->entry->next = newElement;
        newElement->previous = backlog->entry;
    } else {
        backlog->entry = newElement;
        backlog->entry->next = newElement;
        backlog->entry->previous = newElement;
    }

    backlog->elements = backlog->elements + 1;

    return backlog->elements;
}

static int32_t backlogDel(struct vpBacklog *backlog) {
    while(backlog->elements > 0) {
        if(backlogDelElement(backlog, backlog->entry) < 0) {
            LOG("Error deleting element at %p from the backlog. %d elements remain in the list.",
                backlog->entry, backlog->elements);
            return FALSE;
        }
    }

    free(backlog);

    return TRUE;
}

static int32_t vpHandleBacklog(struct vpListElement *currentVp,
                               struct viewerState *viewerState,
                               struct stateInfo *state) {

    struct vpBacklogElement *currentElement = NULL,
                            *nextElement = NULL;
    Byte *cube = NULL;
    uint32_t elements = 0,
             i = 0;

    if(currentVp->backlog->entry == NULL) {
        LOG("Called vpHandleBacklog, but there is no backlog.");
        return FALSE;
    }

    elements = currentVp->backlog->elements;
    currentElement = currentVp->backlog->entry;

    for(i = 0; i < elements; i++)  {
        nextElement = currentElement->next;

        if(currentElement->cubeType == CUBE_DATA) {
            SDL_LockMutex(state->protectCube2Pointer);
            cube = ht_get(state->Dc2Pointer, currentElement->cube);
            SDL_UnlockMutex(state->protectCube2Pointer);

            if(cube == HT_FAILURE) {
                /* */
            }
            else {
                dcSliceExtract(cube,
                               currentElement->slice,
                               currentElement->dcOffset,
                               currentVp->viewPort,
                               state);

                glBindTexture(GL_TEXTURE_2D, currentVp->viewPort->texture.texHandle);
                glTexSubImage2D(GL_TEXTURE_2D,
                                0,
                                currentElement->x_px,
                                currentElement->y_px,
                                state->cubeEdgeLength,
                                state->cubeEdgeLength,
                                GL_RGB,
                                GL_UNSIGNED_BYTE,
                                currentElement->slice);
                glBindTexture(GL_TEXTURE_2D, 0);
                backlogDelElement(currentVp->backlog, currentElement);
            }
        }
        else if(currentElement->cubeType == CUBE_OVERLAY) {
            SDL_LockMutex(state->protectCube2Pointer);
            cube = ht_get(state->Oc2Pointer, currentElement->cube);
            SDL_UnlockMutex(state->protectCube2Pointer);

            if(cube == HT_FAILURE) {
                /* */
            }
            else {
                ocSliceExtract(cube,
                               currentElement->slice,
                               currentElement->dcOffset,
                               currentVp->viewPort,
                               state);

                glBindTexture(GL_TEXTURE_2D, currentVp->viewPort->texture.overlayHandle);
                glTexSubImage2D(GL_TEXTURE_2D,
                                0,
                                currentElement->x_px,
                                currentElement->y_px,
                                state->cubeEdgeLength,
                                state->cubeEdgeLength,
                                GL_RGBA,
                                GL_UNSIGNED_BYTE,
                                currentElement->slice);
                glBindTexture(GL_TEXTURE_2D, 0);
                backlogDelElement(currentVp->backlog, currentElement);
            }
        }

        currentElement = nextElement;
    }

    if(currentVp->backlog->elements != 0)
        return FALSE;
    else
        return TRUE;
}

static uint32_t vpGenerateTexture(
    struct vpListElement *currentVp, struct viewerState *viewerState,
    struct stateInfo *state) {
    // Load the texture for a viewport by going through all relevant datacubes and copying slices
    // from those cubes into the texture.

    uint32_t x_px = 0, x_dc = 0, y_px = 0, y_dc = 0;
    Coordinate upperLeftDc, currentDc, currentPosition_dc;
    Byte *datacube = NULL, *overlayCube = NULL;
    uint32_t dcOffset = 0, index = 0;

    currentPosition_dc = Px2DcCoord(viewerState->currentPosition, state);
    upperLeftDc = Px2DcCoord(currentVp->viewPort->texture.leftUpperPxInAbsPx, state);

    // We calculate the coordinate of the DC that holds the slice that makes up the upper left
    // corner of our texture.
    // dcOffset is the offset by which we can index into a datacube to extract the first byte of
    // slice relevant to the texture for this viewport.
    //
    // Rounding should be explicit!
    switch(currentVp->viewPort->type) {
        case SLICE_XY:
            dcOffset = state->cubeSliceArea
                       * (viewerState->currentPosition.z - state->cubeEdgeLength
                       * currentPosition_dc.z);
            break;

        case SLICE_XZ:
            dcOffset = state->cubeEdgeLength
                       * (viewerState->currentPosition.y - state->cubeEdgeLength
                       * currentPosition_dc.y);
            break;

        case SLICE_YZ:
            dcOffset = viewerState->currentPosition.x - state->cubeEdgeLength
                       * currentPosition_dc.x;
            break;

        default:
            LOG("No such slice view: %d.", currentVp->viewPort->type);
            return FALSE;
    }

    // We iterate over the texture with x and y being in a temporary coordinate
    // system local to this texture.
    for(x_dc = 0; x_dc < currentVp->viewPort->texture.usedTexLengthDc; x_dc++) {
        for(y_dc = 0; y_dc < currentVp->viewPort->texture.usedTexLengthDc; y_dc++) {
            x_px = x_dc * state->cubeEdgeLength;
            y_px = y_dc * state->cubeEdgeLength;

            switch(currentVp->viewPort->type) {
                // With an x/y-coordinate system in a viewport, we get the following
                // mapping from viewport (slice) coordinates to global (dc)
                // coordinates:
                // XY-slice: x local is x global, y local is y global
                // XZ-slice: x local is x global, y local is z global
                // YZ-slice: x local is y global, y local is z global.
            case SLICE_XY:
                SET_COORDINATE(currentDc,
                               upperLeftDc.x + x_dc,
                               upperLeftDc.y + y_dc,
                               upperLeftDc.z);
                break;
            case SLICE_XZ:
                SET_COORDINATE(currentDc,
                               upperLeftDc.x + x_dc,
                               upperLeftDc.y,
                               upperLeftDc.z + y_dc);
                break;
            case SLICE_YZ:
                SET_COORDINATE(currentDc,
                               upperLeftDc.x,
                               upperLeftDc.y + x_dc,
                               upperLeftDc.z + y_dc);
                break;
            default:
                LOG("No such slice type (%d) in vpGenerateTexture.", currentVp->viewPort->type);
            }

            SDL_LockMutex(state->protectCube2Pointer);
            datacube = ht_get(state->Dc2Pointer, currentDc);
            overlayCube = ht_get(state->Oc2Pointer, currentDc);
            SDL_UnlockMutex(state->protectCube2Pointer);

            /*
             *  Take care of the data textures.
             *
             */
            glBindTexture(GL_TEXTURE_2D,
                          currentVp->viewPort->texture.texHandle);

            glPixelStorei(GL_UNPACK_ALIGNMENT, 1);

            // This is used to index into the texture. texData[index] is the first
            // byte of the datacube slice at position (x_dc, y_dc) in the texture.
            index = texIndex(x_dc, y_dc, 3, &(currentVp->viewPort->texture), state);

            if(datacube == HT_FAILURE) {
                backlogAddElement(currentVp->backlog,
                                  currentDc,
                                  dcOffset,
                                  &(viewerState->texData[index]),
                                  x_px,
                                  y_px,
                                  CUBE_DATA);

                glTexSubImage2D(GL_TEXTURE_2D,
                                0,
                                x_px,
                                y_px,
                                state->cubeEdgeLength,
                                state->cubeEdgeLength,
                                GL_RGB,
                                GL_UNSIGNED_BYTE,
                                viewerState->defaultTexData);
            }
            else {
                dcSliceExtract(datacube,
                               &(viewerState->texData[index]),
                               dcOffset,
                               currentVp->viewPort,
                               state);

                glTexSubImage2D(GL_TEXTURE_2D,
                                0,
                                x_px,
                                y_px,
                                state->cubeEdgeLength,
                                state->cubeEdgeLength,
                                GL_RGB,
                                GL_UNSIGNED_BYTE,
                                &(viewerState->texData[index]));
            }

            /*
             *  Take care of the overlay textures.
             *
             */
            if(state->overlay) {
                glBindTexture(GL_TEXTURE_2D,
                              currentVp->viewPort->texture.overlayHandle);

                glPixelStorei(GL_UNPACK_ALIGNMENT, 1);

                // This is used to index into the texture. texData[index] is the first
                // byte of the datacube slice at position (x_dc, y_dc) in the texture.
                index = texIndex(x_dc, y_dc, 4, &(currentVp->viewPort->texture), state);

                if(overlayCube == HT_FAILURE) {
                    backlogAddElement(currentVp->backlog,
                                      currentDc,
                                      dcOffset * OBJID_BYTES,
                                      &(viewerState->overlayData[index]),
                                      x_px,
                                      y_px,
                                      CUBE_OVERLAY);

                    glTexSubImage2D(GL_TEXTURE_2D,
                                    0,
                                    x_px,
                                    y_px,
                                    state->cubeEdgeLength,
                                    state->cubeEdgeLength,
                                    GL_RGBA,
                                    GL_UNSIGNED_BYTE,
                                    viewerState->defaultOverlayData);
                }
                else {
                    ocSliceExtract(overlayCube,
                                   &(viewerState->overlayData[index]),
                                   dcOffset * OBJID_BYTES,
                                   currentVp->viewPort,
                                   state);

                    glTexSubImage2D(GL_TEXTURE_2D,
                                    0,
                                    x_px,
                                    y_px,
                                    state->cubeEdgeLength,
                                    state->cubeEdgeLength,
                                    GL_RGBA,
                                    GL_UNSIGNED_BYTE,
                                    &(viewerState->overlayData[index]));
                }
            }
        }
    }
    glBindTexture(GL_TEXTURE_2D, 0);
    return TRUE;
}

uint32_t initializeTextures() {
    uint32_t i = 0;

    /*problem of deleting textures when calling again after resize?! TDitem */
    for(i = 0; i < state->viewerState->numberViewPorts; i++) {
        if(state->viewerState->viewPorts[i].type != VIEWPORT_SKELETON) {
            //state->viewerState->viewPorts[i].displayList = glGenLists(1);
            glGenTextures(1, &state->viewerState->viewPorts[i].texture.texHandle);
            if(state->overlay)
                glGenTextures(1, &state->viewerState->viewPorts[i].texture.overlayHandle);
        }
    }

    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);

    for(i = 0; i < state->viewerState->numberViewPorts; i++) {
        if(state->viewerState->viewPorts[i].type == VIEWPORT_SKELETON)
            continue;

        /*
         *  Handle data textures.
         *
         */

        glBindTexture(GL_TEXTURE_2D, state->viewerState->viewPorts[i].texture.texHandle);

        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);

        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, state->viewerState->filterType);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, state->viewerState->filterType);

        glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_REPLACE);

        // loads an empty texture into video memory - during user movement, this
        // texture is updated via glTexSubImage2D in vpGenerateTexture & vpHandleBacklog
        // We need GL_RGB as texture internal format to color the textures

        glTexImage2D(GL_TEXTURE_2D,
                     0,
                     GL_RGB,
                     state->viewerState->viewPorts[i].texture.edgeLengthPx,
                     state->viewerState->viewPorts[i].texture.edgeLengthPx,
                     0,
                     GL_RGB,
                     GL_UNSIGNED_BYTE,
                     state->viewerState->defaultTexData);

        /*
         *  Handle overlay textures.
         *
         */

        if(state->overlay) {
            glBindTexture(GL_TEXTURE_2D, state->viewerState->viewPorts[i].texture.overlayHandle);

            //Set the parameters for the texture.
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);

            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, state->viewerState->filterType);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, state->viewerState->filterType);

            glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_REPLACE);

            glTexImage2D(GL_TEXTURE_2D,
                         0,
                         GL_RGBA,
                         state->viewerState->viewPorts[i].texture.edgeLengthPx,
                         state->viewerState->viewPorts[i].texture.edgeLengthPx,
                         0,
                         GL_RGBA,
                         GL_UNSIGNED_BYTE,
                         state->viewerState->defaultOverlayData);
        }
    }

    return TRUE;
}

static int32_t texIndex(uint32_t x,
                        uint32_t y,
                        uint32_t colorMultiplicationFactor,
                        struct viewPortTexture *texture,
                        struct stateInfo *state) {

    uint32_t index = 0;

    index = x * state->cubeSliceArea + y
            * (texture->edgeLengthDc * state->cubeSliceArea)
            * colorMultiplicationFactor;

    return index;
}

static uint32_t calcLeftUpperTexAbsPx(struct stateInfo *state) {
    uint32_t i = 0;
    Coordinate currentPosition_dc;
    struct viewerState *viewerState = state->viewerState;

    currentPosition_dc = Px2DcCoord(viewerState->currentPosition, state);

    //iterate over all viewports
    //this function has to be called after the texture changed or the user moved, in the sense of a
    //realignment of the data
    for (i = 0; i < viewerState->numberViewPorts; i++) {
        switch (viewerState->viewPorts[i].type) {
        case VIEWPORT_XY:
            //Set the coordinate of left upper data pixel currently stored in the texture
            SET_COORDINATE(viewerState->viewPorts[i].texture.leftUpperPxInAbsPx,
                           (currentPosition_dc.x - (viewerState->viewPorts[i].texture.usedTexLengthDc / 2)) * state->cubeEdgeLength,
                           (currentPosition_dc.y - (viewerState->viewPorts[i].texture.usedTexLengthDc / 2)) * state->cubeEdgeLength,
                           currentPosition_dc.z * state->cubeEdgeLength);

            //Set the coordinate of left upper data pixel currently displayed on screen
            //The following lines are dependent on the current VP orientation, so rotation of VPs messes that
            //stuff up! A more general solution would be better.
            SET_COORDINATE(state->viewerState->viewPorts[i].leftUpperDataPxOnScreen,
                           viewerState->currentPosition.x - (int)((viewerState->viewPorts[i].texture.displayedEdgeLengthX / 2.) / viewerState->viewPorts[i].texture.texUnitsPerDataPx),
                           viewerState->currentPosition.y - (int)((viewerState->viewPorts[i].texture.displayedEdgeLengthY / 2.) / viewerState->viewPorts[i].texture.texUnitsPerDataPx),
                           viewerState->currentPosition.z);

            break;

        case VIEWPORT_XZ:
            //Set the coordinate of left upper data pixel currently stored in the texture
            SET_COORDINATE(viewerState->viewPorts[i].texture.leftUpperPxInAbsPx,
                           (currentPosition_dc.x - (viewerState->viewPorts[i].texture.usedTexLengthDc / 2)) * state->cubeEdgeLength,
                           currentPosition_dc.y * state->cubeEdgeLength,
                           (currentPosition_dc.z - (viewerState->viewPorts[i].texture.usedTexLengthDc / 2)) * state->cubeEdgeLength);

            //Set the coordinate of left upper data pixel currently displayed on screen
            //The following lines are dependent on the current VP orientation, so rotation of VPs messes that
            //stuff up! A more general solution would be better.
            SET_COORDINATE(state->viewerState->viewPorts[i].leftUpperDataPxOnScreen,
                           viewerState->currentPosition.x - (int)((viewerState->viewPorts[i].texture.displayedEdgeLengthX / 2.) / viewerState->viewPorts[i].texture.texUnitsPerDataPx),
                           viewerState->currentPosition.y ,
                           viewerState->currentPosition.z - (int)((viewerState->viewPorts[i].texture.displayedEdgeLengthY / 2.) / viewerState->viewPorts[i].texture.texUnitsPerDataPx));

            break;

        case VIEWPORT_YZ:
            //Set the coordinate of left upper data pixel currently stored in the texture
            SET_COORDINATE(viewerState->viewPorts[i].texture.leftUpperPxInAbsPx,
                           currentPosition_dc.x * state->cubeEdgeLength,
                           (currentPosition_dc.y - (viewerState->viewPorts[i].texture.usedTexLengthDc / 2)) * state->cubeEdgeLength,
                           (currentPosition_dc.z - (viewerState->viewPorts[i].texture.usedTexLengthDc / 2)) * state->cubeEdgeLength);

            //Set the coordinate of left upper data pixel currently displayed on screen
            //The following lines are dependent on the current VP orientation, so rotation of VPs messes that
            //stuff up! A more general solution would be better.
            SET_COORDINATE(state->viewerState->viewPorts[i].leftUpperDataPxOnScreen,
                           viewerState->currentPosition.x ,
                           viewerState->currentPosition.y - (int)((viewerState->viewPorts[i].texture.displayedEdgeLengthX / 2.)  / viewerState->viewPorts[i].texture.texUnitsPerDataPx),
                           viewerState->currentPosition.z - (int)((viewerState->viewPorts[i].texture.displayedEdgeLengthY / 2.) / viewerState->viewPorts[i].texture.texUnitsPerDataPx));


            break;
        default:

            viewerState->viewPorts[i].texture.leftUpperPxInAbsPx.x = 0;
            viewerState->viewPorts[i].texture.leftUpperPxInAbsPx.y = 0;
            viewerState->viewPorts[i].texture.leftUpperPxInAbsPx.z = 0;
        }
    }

    return TRUE;
}

/* relative movement depending on current position */
uint32_t userMove(
    int32_t x, int32_t y, int32_t z,
    int32_t serverMovement, struct stateInfo *state) {

    struct viewerState *viewerState = state->viewerState;

    Coordinate lastPosition_dc;
    Coordinate newPosition_dc;

    //The skeleton VP view has to be updated after a current pos change
    state->skeletonState->viewChanged = TRUE;
    if(state->skeletonState->showIntersections)
        state->skeletonState->skeletonSliceVPchanged = TRUE;

    // This determines whether the server will broadcast the coordinate change
    // to its client or not.

    lastPosition_dc = Px2DcCoord(viewerState->currentPosition, state);

    viewerState->userMove = TRUE;

    if ((viewerState->currentPosition.x + x) >= 0 &&
        (viewerState->currentPosition.x + x) <= state->boundary.x &&
        (viewerState->currentPosition.y + y) >= 0 &&
        (viewerState->currentPosition.y + y) <= state->boundary.y &&
        (viewerState->currentPosition.z + z) >= 0 &&
        (viewerState->currentPosition.z + z) <= state->boundary.z) {
            viewerState->currentPosition.x += x;
            viewerState->currentPosition.y += y;
            viewerState->currentPosition.z += z;
    }
    else {
        LOG("Position (%d, %d, %d) out of bounds",
            viewerState->currentPosition.x + x + 1,
            viewerState->currentPosition.y + y + 1,
            viewerState->currentPosition.z + z + 1);
    }

    calcLeftUpperTexAbsPx(state);
    recalcTextureOffsets();
    newPosition_dc = Px2DcCoord(viewerState->currentPosition, state);

    if(serverMovement == TELL_COORDINATE_CHANGE &&
       state->clientState->connected == TRUE &&
       state->clientState->synchronizePosition)
        broadcastPosition(state,
                          viewerState->currentPosition.x,
                          viewerState->currentPosition.y,
                          viewerState->currentPosition.z);

    /* TDitem
    printf("temp x: %d\n", tempConfig->viewerState->currentPosition.x);
    printf("temp x: %d\n", state->viewerState->currentPosition.x);
    */

    /*
    printf("temp y: %d\n", tempConfig->viewerState->currentPosition.y);
    printf("temp y: %d\n", state->viewerState->currentPosition.y);

    printf("temp z: %d\n", tempConfig->viewerState->currentPosition.z);
    printf("temp z: %d\n", state->viewerState->currentPosition.z);
    */

    tempConfig->viewerState->currentPosition.x = viewerState->currentPosition.x;
    tempConfig->viewerState->currentPosition.y = viewerState->currentPosition.y;
    tempConfig->viewerState->currentPosition.z = viewerState->currentPosition.z;

    if(!COMPARE_COORDINATE(newPosition_dc, lastPosition_dc)) {
        state->viewerState->superCubeChanged = TRUE;

        sendLoadSignal(viewerState->currentPosition.x,
                       viewerState->currentPosition.y,
                       viewerState->currentPosition.z);
    }
    checkIdleTime();
    return TRUE;
}

int32_t updatePosition(struct stateInfo *state, int32_t serverMovement) {
    Coordinate jump;

    if(COMPARE_COORDINATE(tempConfig->viewerState->currentPosition, state->viewerState->currentPosition) != TRUE) {
        jump.x = tempConfig->viewerState->currentPosition.x - state->viewerState->currentPosition.x;
        jump.y = tempConfig->viewerState->currentPosition.y - state->viewerState->currentPosition.y;
        jump.z = tempConfig->viewerState->currentPosition.z - state->viewerState->currentPosition.z;
        userMove(jump.x, jump.y, jump.z, serverMovement, state);
    }

    return TRUE;
}

int32_t findVPnumByWindowCoordinate(uint32_t xScreen, uint32_t yScreen, struct stateInfo *state) {
    uint32_t tempNum;

    tempNum = -1;
    /* TDitem
    for(i = 0; i < state->viewerState->numberViewPorts; i++) {
        if((xScreen >= state->viewerState->viewPorts[i].lowerLeftCorner.x) && (xScreen <= (state->viewerState->viewPorts[i].lowerLeftCorner.x + state->viewerState->viewPorts[i].edgeLength))) {
            if((yScreen >= (((state->viewerState->viewPorts[i].lowerLeftCorner.y - state->viewerState->screenSizeY) * -1) - state->viewerState->viewPorts[i].edgeLength)) && (yScreen <= ((state->viewerState->viewPorts[i].lowerLeftCorner.y - state->viewerState->screenSizeY) * -1))) {
                //Window coordinate lies in that VP
                tempNum = i;
            }
        }
    }
    //The VP on top (if there are multiple VPs on this coordinate) or -1 is returned.
    */
    return tempNum;
}

uint32_t recalcTextureOffsets() {
    uint32_t i;
    float midX, midY;

    midX = midY = 0.;

    /* Every time the texture offset coords change,
    the skeleton VP must be updated. */
    state->skeletonState->viewChanged = TRUE;

    for(i = 0; i < state->viewerState->numberViewPorts; i++) {
        /* Do this only for orthogonal VPs... */
        if (state->viewerState->viewPorts[i].type == VIEWPORT_XY
                || state->viewerState->viewPorts[i].type == VIEWPORT_XZ
                || state->viewerState->viewPorts[i].type == VIEWPORT_YZ) {
            /*Don't remove /2 *2, integer division! */
            state->viewerState->viewPorts[i].texture.displayedEdgeLengthX =
                state->viewerState->viewPorts[i].texture.displayedEdgeLengthY =
                    ((float)(((state->M / 2) * 2 - 1) * state->cubeEdgeLength))
                    / ((float)state->viewerState->viewPorts[i].texture.edgeLengthPx);


            //Multiply the zoom factor. (only truncation possible! 1 stands for minimal zoom)
            state->viewerState->viewPorts[i].texture.displayedEdgeLengthX *=
                state->viewerState->viewPorts[i].texture.zoomLevel;
            state->viewerState->viewPorts[i].texture.displayedEdgeLengthY *=
                state->viewerState->viewPorts[i].texture.zoomLevel;

            //... and for the right orthogonal VP
            switch(state->viewerState->viewPorts[i].type) {
                case VIEWPORT_XY:
                    //Aspect ratio correction..
                    if(state->viewerState->voxelXYRatio < 1)
                        state->viewerState->viewPorts[i].texture.displayedEdgeLengthY *=
                            state->viewerState->voxelXYRatio;
                    else
                        state->viewerState->viewPorts[i].texture.displayedEdgeLengthX /=
                            state->viewerState->voxelXYRatio;

                    //Display only entire pixels (only truncation possible!)
                    state->viewerState->viewPorts[i].texture.displayedEdgeLengthX =
                        (float) (
                            (int) (
                                state->viewerState->viewPorts[i].texture.displayedEdgeLengthX
                                / 2.
                                / state->viewerState->viewPorts[i].texture.texUnitsPerDataPx
                            )
                            * state->viewerState->viewPorts[i].texture.texUnitsPerDataPx
                        )
                        * 2.;

                    state->viewerState->viewPorts[i].texture.displayedEdgeLengthY =
                        (float)
                        (((int)(state->viewerState->viewPorts[i].texture.displayedEdgeLengthY /
                        2. /
                        state->viewerState->viewPorts[i].texture.texUnitsPerDataPx)) *
                        state->viewerState->viewPorts[i].texture.texUnitsPerDataPx) *
                        2.;

                    // Update screen pixel to data pixel mapping values
                    state->viewerState->viewPorts[i].screenPxXPerDataPx =
                        (float)state->viewerState->viewPorts[i].edgeLength /
                        (state->viewerState->viewPorts[i].texture.displayedEdgeLengthX /
                         state->viewerState->viewPorts[i].texture.texUnitsPerDataPx);

                    state->viewerState->viewPorts[i].screenPxYPerDataPx =
                        (float)state->viewerState->viewPorts[i].edgeLength /
                        (state->viewerState->viewPorts[i].texture.displayedEdgeLengthY /
                         state->viewerState->viewPorts[i].texture.texUnitsPerDataPx);

                    // Pixels on the screen per 1 unit in the data coordinate system at the
                    // original magnification.
                    state->viewerState->viewPorts[i].screenPxXPerOrigMagUnit =
                        state->viewerState->viewPorts[i].screenPxXPerDataPx *
                        state->magnification;

                    state->viewerState->viewPorts[i].screenPxYPerOrigMagUnit =
                        state->viewerState->viewPorts[i].screenPxYPerDataPx *
                        state->magnification;

                    state->viewerState->viewPorts[i].displayedlengthInNmX =
                        state->viewerState->voxelDimX *
                        (state->viewerState->viewPorts[i].texture.displayedEdgeLengthX /
                         state->viewerState->viewPorts[i].texture.texUnitsPerDataPx);

                    state->viewerState->viewPorts[i].displayedlengthInNmY =
                        state->viewerState->voxelDimY *
                        (state->viewerState->viewPorts[i].texture.displayedEdgeLengthY /
                        state->viewerState->viewPorts[i].texture.texUnitsPerDataPx);

                    // scale to 0 - 1
                    midX = (float)(state->viewerState->currentPosition.x -
                             state->viewerState->viewPorts[i].texture.leftUpperPxInAbsPx.x) /
                             (float)state->viewerState->viewPorts[i].texture.edgeLengthPx;
                    midY = (float)(state->viewerState->currentPosition.y -
                             state->viewerState->viewPorts[i].texture.leftUpperPxInAbsPx.y) /
                             (float)state->viewerState->viewPorts[i].texture.edgeLengthPx;

                    //Update state->viewerState->viewPorts[i].leftUpperDataPxOnScreen with this call
                    calcLeftUpperTexAbsPx(state);

                    //Offsets for crosshair
                    state->viewerState->viewPorts[i].texture.xOffset = ((float)(state->viewerState->currentPosition.x - state->viewerState->viewPorts[i].leftUpperDataPxOnScreen.x)) * state->viewerState->viewPorts[i].screenPxXPerDataPx + 0.5 * state->viewerState->viewPorts[i].screenPxXPerDataPx;
                    state->viewerState->viewPorts[i].texture.yOffset = ((float)(state->viewerState->currentPosition.y - state->viewerState->viewPorts[i].leftUpperDataPxOnScreen.y)) * state->viewerState->viewPorts[i].screenPxYPerDataPx + 0.5 * state->viewerState->viewPorts[i].screenPxYPerDataPx;

                    break;
                case VIEWPORT_XZ:
                    //Aspect ratio correction..
                    if(state->viewerState->voxelXYtoZRatio < 1) state->viewerState->viewPorts[i].texture.displayedEdgeLengthY *= state->viewerState->voxelXYtoZRatio;
                    else state->viewerState->viewPorts[i].texture.displayedEdgeLengthX /= state->viewerState->voxelXYtoZRatio;

                    //Display only entire pixels (only truncation possible!)
                    state->viewerState->viewPorts[i].texture.displayedEdgeLengthX = (float)(((int)(state->viewerState->viewPorts[i].texture.displayedEdgeLengthX / 2. / state->viewerState->viewPorts[i].texture.texUnitsPerDataPx)) * state->viewerState->viewPorts[i].texture.texUnitsPerDataPx) * 2.;
                    state->viewerState->viewPorts[i].texture.displayedEdgeLengthY = (float)(((int)(state->viewerState->viewPorts[i].texture.displayedEdgeLengthY / 2. / state->viewerState->viewPorts[i].texture.texUnitsPerDataPx)) * state->viewerState->viewPorts[i].texture.texUnitsPerDataPx) * 2.;

                    //Update screen pixel to data pixel mapping values
                    state->viewerState->viewPorts[i].screenPxXPerDataPx =
                        (float)state->viewerState->viewPorts[i].edgeLength /
                        (state->viewerState->viewPorts[i].texture.displayedEdgeLengthX /
                         state->viewerState->viewPorts[i].texture.texUnitsPerDataPx);

                    state->viewerState->viewPorts[i].screenPxYPerDataPx =
                        (float)state->viewerState->viewPorts[i].edgeLength /
                        (state->viewerState->viewPorts[i].texture.displayedEdgeLengthY /
                         state->viewerState->viewPorts[i].texture.texUnitsPerDataPx);

                    // Pixels on the screen per 1 unit in the data coordinate system at the
                    // original magnification.
                    state->viewerState->viewPorts[i].screenPxXPerOrigMagUnit =
                        state->viewerState->viewPorts[i].screenPxXPerDataPx *
                        state->magnification;

                    state->viewerState->viewPorts[i].screenPxYPerOrigMagUnit =
                        state->viewerState->viewPorts[i].screenPxYPerDataPx *
                        state->magnification;

                    state->viewerState->viewPorts[i].displayedlengthInNmX =
                        state->viewerState->voxelDimX *
                        (state->viewerState->viewPorts[i].texture.displayedEdgeLengthX /
                         state->viewerState->viewPorts[i].texture.texUnitsPerDataPx);

                    state->viewerState->viewPorts[i].displayedlengthInNmY =
                        state->viewerState->voxelDimZ *
                        (state->viewerState->viewPorts[i].texture.displayedEdgeLengthY /
                         state->viewerState->viewPorts[i].texture.texUnitsPerDataPx);

                    midX = ((float)(state->viewerState->currentPosition.x - state->viewerState->viewPorts[i].texture.leftUpperPxInAbsPx.x))
                           / (float)state->viewerState->viewPorts[i].texture.edgeLengthPx; //scale to 0 - 1
                    midY = ((float)(state->viewerState->currentPosition.z - state->viewerState->viewPorts[i].texture.leftUpperPxInAbsPx.z))
                           / (float)state->viewerState->viewPorts[i].texture.edgeLengthPx; //scale to 0 - 1

                    //Update state->viewerState->viewPorts[i].leftUpperDataPxOnScreen with this call
                    calcLeftUpperTexAbsPx(state);

                    //Offsets for crosshair
                    state->viewerState->viewPorts[i].texture.xOffset = ((float)(state->viewerState->currentPosition.x - state->viewerState->viewPorts[i].leftUpperDataPxOnScreen.x)) * state->viewerState->viewPorts[i].screenPxXPerDataPx + 0.5 * state->viewerState->viewPorts[i].screenPxXPerDataPx;
                    state->viewerState->viewPorts[i].texture.yOffset = ((float)(state->viewerState->currentPosition.z - state->viewerState->viewPorts[i].leftUpperDataPxOnScreen.z)) * state->viewerState->viewPorts[i].screenPxYPerDataPx + 0.5 * state->viewerState->viewPorts[i].screenPxYPerDataPx;

                    break;
                case VIEWPORT_YZ:
                    //Aspect ratio correction..
                    if(state->viewerState->voxelXYtoZRatio < 1) state->viewerState->viewPorts[i].texture.displayedEdgeLengthY *= state->viewerState->voxelXYtoZRatio;
                    else state->viewerState->viewPorts[i].texture.displayedEdgeLengthX /= state->viewerState->voxelXYtoZRatio;

                    //Display only entire pixels (only truncation possible!)
                    state->viewerState->viewPorts[i].texture.displayedEdgeLengthX = (float)(((int)(state->viewerState->viewPorts[i].texture.displayedEdgeLengthX / 2. / state->viewerState->viewPorts[i].texture.texUnitsPerDataPx)) * state->viewerState->viewPorts[i].texture.texUnitsPerDataPx) * 2.;
                    state->viewerState->viewPorts[i].texture.displayedEdgeLengthY = (float)(((int)(state->viewerState->viewPorts[i].texture.displayedEdgeLengthY / 2. / state->viewerState->viewPorts[i].texture.texUnitsPerDataPx)) * state->viewerState->viewPorts[i].texture.texUnitsPerDataPx) * 2.;

                    // Update screen pixel to data pixel mapping values
                    // WARNING: YZ IS ROTATED AND MIRRORED! So screenPxXPerDataPx
                    // corresponds to displayedEdgeLengthY and so on.
                    state->viewerState->viewPorts[i].screenPxXPerDataPx =
                        (float)state->viewerState->viewPorts[i].edgeLength /
                        (state->viewerState->viewPorts[i].texture.displayedEdgeLengthY /
                         state->viewerState->viewPorts[i].texture.texUnitsPerDataPx);

                    state->viewerState->viewPorts[i].screenPxYPerDataPx =
                        (float)state->viewerState->viewPorts[i].edgeLength /
                        (state->viewerState->viewPorts[i].texture.displayedEdgeLengthX /
                         state->viewerState->viewPorts[i].texture.texUnitsPerDataPx);

                    // Pixels on the screen per 1 unit in the data coordinate system at the
                    // original magnification.
                    state->viewerState->viewPorts[i].screenPxXPerOrigMagUnit =
                        state->viewerState->viewPorts[i].screenPxXPerDataPx *
                        state->magnification;

                    state->viewerState->viewPorts[i].screenPxYPerOrigMagUnit =
                        state->viewerState->viewPorts[i].screenPxYPerDataPx *
                        state->magnification;

                    state->viewerState->viewPorts[i].displayedlengthInNmX =
                        state->viewerState->voxelDimZ *
                        (state->viewerState->viewPorts[i].texture.displayedEdgeLengthY /
                         state->viewerState->viewPorts[i].texture.texUnitsPerDataPx);

                    state->viewerState->viewPorts[i].displayedlengthInNmY =
                        state->viewerState->voxelDimY *
                        (state->viewerState->viewPorts[i].texture.displayedEdgeLengthX /
                         state->viewerState->viewPorts[i].texture.texUnitsPerDataPx);

                    midX = ((float)(state->viewerState->currentPosition.y - state->viewerState->viewPorts[i].texture.leftUpperPxInAbsPx.y))
                           / (float)state->viewerState->viewPorts[i].texture.edgeLengthPx; //scale to 0 - 1
                    midY = ((float)(state->viewerState->currentPosition.z - state->viewerState->viewPorts[i].texture.leftUpperPxInAbsPx.z))
                           / (float)state->viewerState->viewPorts[i].texture.edgeLengthPx; //scale to 0 - 1

                    //Update state->viewerState->viewPorts[i].leftUpperDataPxOnScreen with this call
                    calcLeftUpperTexAbsPx(state);

                    //Offsets for crosshair
                    state->viewerState->viewPorts[i].texture.xOffset = ((float)(state->viewerState->currentPosition.z - state->viewerState->viewPorts[i].leftUpperDataPxOnScreen.z)) * state->viewerState->viewPorts[i].screenPxXPerDataPx + 0.5 * state->viewerState->viewPorts[i].screenPxXPerDataPx;
                    state->viewerState->viewPorts[i].texture.yOffset = ((float)(state->viewerState->currentPosition.y - state->viewerState->viewPorts[i].leftUpperDataPxOnScreen.y)) * state->viewerState->viewPorts[i].screenPxYPerDataPx + 0.5 * state->viewerState->viewPorts[i].screenPxYPerDataPx;

                    break;
            }

            //Calculate the vertices in texture coordinates
            state->viewerState->viewPorts[i].texture.texLUx = midX - (state->viewerState->viewPorts[i].texture.displayedEdgeLengthX / 2.);
            state->viewerState->viewPorts[i].texture.texLUy = midY - (state->viewerState->viewPorts[i].texture.displayedEdgeLengthY / 2.);
            state->viewerState->viewPorts[i].texture.texRUx = midX + (state->viewerState->viewPorts[i].texture.displayedEdgeLengthX / 2.);
            state->viewerState->viewPorts[i].texture.texRUy = state->viewerState->viewPorts[i].texture.texLUy;
            state->viewerState->viewPorts[i].texture.texRLx = state->viewerState->viewPorts[i].texture.texRUx;
            state->viewerState->viewPorts[i].texture.texRLy = midY + (state->viewerState->viewPorts[i].texture.displayedEdgeLengthY / 2.);
            state->viewerState->viewPorts[i].texture.texLLx = state->viewerState->viewPorts[i].texture.texLUx;
            state->viewerState->viewPorts[i].texture.texLLy = state->viewerState->viewPorts[i].texture.texRLy;


        }
    }
    //Reload the height/width-windows in viewports
    reloadDataSizeWin(state);
    return TRUE;
}

int32_t refreshViewports(struct stateInfo *state) {
    SDL_Event redrawEvent;

    redrawEvent.type = SDL_USEREVENT;
    redrawEvent.user.code = USEREVENT_REDRAW;

    SDL_PushEvent(&redrawEvent);

    return TRUE;
}

int32_t loadTreeColorTable(const char *path, float *table, int32_t type, struct stateInfo *state) {
    FILE *lutFile = NULL;
    uint8_t lutBuffer[RGB_LUTSIZE];
    int32_t readBytes = 0, i = 0;
    uint32_t size = RGB_LUTSIZE;

    // The b is for compatibility with non-UNIX systems and denotes a
    // binary file.
    LOG("Reading Tree LUT at %s\n", path);

    lutFile = fopen(path, "rb");
    if(lutFile == NULL) {
        LOG("Unable to open Tree LUT at %s.", path);
        return FALSE;
    }

    if(type != GL_RGB) {
        AG_TextError("Tree colors only support RGB colors. Your color type is: %x", type);
        LOG("Chosen color was of type %x, but expected GL_RGB", type);
        return FALSE;
    }

    readBytes = (int32_t)fread(lutBuffer, 1, size, lutFile);
    if(readBytes != size) {
        LOG("Could read only %d bytes from LUT file %s. Expected %d bytes", readBytes, path, size);
        if(fclose(lutFile) != 0) {
            LOG("Additionally, an error occured closing the file.");
        }
        return FALSE;
    }

    if(fclose(lutFile) != 0) {
        LOG("Error closing LUT file.");
        return FALSE;
    }

    //Get RGB-Values in percent
    for(i = 0; i < 256; i++) {
        table[i]   = lutBuffer[i]/MAX_COLORVAL;
        table[i + 256] = lutBuffer[i+256]/MAX_COLORVAL;
        table[i + 512] = lutBuffer[i + 512]/MAX_COLORVAL;
    }

    treeColorAdjustmentsChanged();
    return TRUE;
}

int32_t loadDatasetColorTable(const char *path, GLuint *table, int32_t type, struct stateInfo *state) {
    FILE *lutFile = NULL;
    uint8_t lutBuffer[RGBA_LUTSIZE];
    int32_t readBytes = 0, i = 0;
    uint32_t size = RGB_LUTSIZE;

    // The b is for compatibility with non-UNIX systems and denotes a
    // binary file.

    LOG("Reading Dataset LUT at %s\n", path);

    lutFile = fopen(path, "rb");
    if(lutFile == NULL) {
        LOG("Unable to open Dataset LUT at %s.", path);
        return FALSE;
    }

    if(type == GL_RGB)
        size = RGB_LUTSIZE;
    else if(type == GL_RGBA)
        size = RGBA_LUTSIZE;
    else {
        LOG("Requested color type %x does not exist.", type);
        return FALSE;
    }

    readBytes = (int32_t)fread(lutBuffer, 1, size, lutFile);
    if(readBytes != size) {
        LOG("Could read only %d bytes from LUT file %s. Expected %d bytes", readBytes, path, size);
        if(fclose(lutFile) != 0) {
            LOG("Additionally, an error occured closing the file.");
        }
        return FALSE;
    }

    if(fclose(lutFile) != 0) {
        LOG("Error closing LUT file.");
        return FALSE;
    }

    if(type == GL_RGB) {
        for(i = 0; i < 256; i++) {
            table[0 * 256 + i] = (GLuint)lutBuffer[i];
            table[1 * 256 + i] = (GLuint)lutBuffer[i + 256];
            table[2 * 256 + i] = (GLuint)lutBuffer[i + 512];
        }
    }
    else if(type == GL_RGBA) {
        for(i = 0; i < 256; i++) {
            table[0 * 256 + i] = (GLuint)lutBuffer[i];
            table[1 * 256 + i] = (GLuint)lutBuffer[i + 256];
            table[2 * 256 + i] = (GLuint)lutBuffer[i + 512];
            table[3 * 256 + i] = (GLuint)lutBuffer[i + 768];
        }
    }

    return TRUE;
}

/* This is from agar, which borrowed from the SDL_SetCursor manpage */
static SDL_Cursor *GenCursor(char *xpm[], int xHot, int yHot) {
    int i = -1, row, col;
    uint8_t data[4 * 32];
    uint8_t mask[4 * 32];
    int w, h;

    sscanf(xpm[0], "%d %d", &w, &h);

    for (row = 0; row < h; row++) {
        for (col = 0; col < w; col++) {
            if (col % 8) {
                data[i] <<= 1;
                mask[i] <<= 1;
            } else {
                i++;
                data[i] = 0;
                mask[i] = 0;
            }
            switch (xpm[row+4][col]) {
            case '.':
                mask[i] |= 0x01;
                break;
            case '+':
                data[i] |= 0x01;
                mask[i] |= 0x01;
                break;
            case ' ':
                break;
            default:
                break;
            }
        }
    }
    return SDL_CreateCursor(data, mask, w, h, xHot, yHot);
}

