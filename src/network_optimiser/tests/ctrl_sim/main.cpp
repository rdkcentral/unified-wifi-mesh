//
//  main.cpp
//
//  Created by Munshi, Soumya on 12/2/25.
//

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "de_reader.h"
#include "de_tester.h"
#include "optimizer_event.h"

int main(int argc, const char * argv[]) {

    de_reader_t *rd;
    de_tester_t *dt;
    int rc;
    optimizer_event_t *ev;

    if ((argc != 2) || (argv[1] == NULL) || (argv[1][0] == '\0')) {
        fprintf(stderr, "Usage: %s <Data_Elements.json>\n", argv[0]);
        return -1;
    }

    rd = new de_reader_t(argv[1]);
    if (rd->init() != 0) {
        printf("%s:%d: Could not initialize reader\n", __func__, __LINE__);
        delete rd;

        return -1;
    }

    dt = new de_tester_t(rd);
    if (dt->init() != 0) {
        dt->deinit();

        printf("%s:%d: Could not initialize de tester\n", __func__, __LINE__);
        delete dt;

        rd->deinit();
        delete rd;

        return -1;
    }

    printf("%s:%d: Successfully initialized data element objects\n", __func__, __LINE__);

    dt->lock();
    while (dt->should_exit() == false) {
        if ((rc = dt->wait()) == ETIMEDOUT) {
            dt->unlock();
            if (rd->has_modified() == true) {
                printf("%s:%d: Data Elements have changed, re-initializing\n", __func__, __LINE__);
                rd->reinit();
            }
            dt->lock();
        } else if ((rc == 0)  || (dt->queue_count() != 0)) {
            dt->unlock();
            while (dt->queue_count()) {
                if ((ev = dt->queue_pop()) == NULL) {
                    dt->lock();
                    continue;
                }
                dt->process_event(ev);
                delete ev;
            }
            dt->lock();
        }
    }
    dt->unlock();

    rd->deinit();
    delete rd;
    
    dt->deinit();
    delete dt;
     
    return 0;
}
