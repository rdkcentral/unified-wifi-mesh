//
//  main.cpp
//  wifi_motion
//
//  Created by Munshi, Soumya on 12/2/25.
//

#include <stdio.h>
#include "optimizer.h"

// global optimizer
optimizer_t g_opt;

optimizer_t *get_optimizer()
{
    return &g_opt;
}

int main(int argc, const char * argv[]) {
    optimizer_type_t type;
    
    if (g_opt.init() != 0) {
        printf("%s:%d: Could not initialize\n", __func__, __LINE__);
        g_opt.deinit(); 
        return -1;
    }

    printf("%s:%d: Init success, retrive operator type to run optimizer\n", __func__, __LINE__);
    
    while ((type = g_opt.get_operator_type()) != optimizer_type_none) {
        switch (type) {
            case optimizer_type_generic:
                g_opt.wait_for_de_change();
                break;

            default:
                if (g_opt.run(type) != 0) {
                    g_opt.wait_for_de_change();
                }
        }
    
    }

    g_opt.deinit(); 
 
    return 0;
}
