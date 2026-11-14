//
//  main.cpp
//
//  Created by Munshi, Soumya on 12/2/25.
//

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "xmidt_optimizer_server.h"

int main(int argc, const char * argv[]) {

    xmidt_optimizer_server_t *opt;

    opt = new xmidt_optimizer_server_t();
    if (opt->init_optimizer_interface("data") != 0) {
        printf("%s:%d: Server init failed\n", __func__, __LINE__);
        return -1;
    }

    opt->start();

    opt->stop();

    opt->deinit_optimizer_interface();
    delete opt; 
    
    return 0;
}
