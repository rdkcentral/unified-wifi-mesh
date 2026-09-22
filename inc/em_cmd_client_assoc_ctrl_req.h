#ifndef EM_CMD_CLIENT_ASSOC_CTRL_REQ_H
#define EM_CMD_CLIENT_ASSOC_CTRL_REQ_H

#include "em_cmd.h"

class em_cmd_client_assoc_ctrl_req_t: public em_cmd_t {

public:

    /**!
     * @brief Constructs a client assoc ctrl req command.
     *
     * @param[in] params The client assoc ctrl req parameters.
     * @param[in] dm     dm reference.
     * @param[in] svc    Service type (controller or agent). Defaults to controller.
     */
    em_cmd_client_assoc_ctrl_req_t(em_cmd_client_assoc_params_t params, dm_easy_mesh_t& dm,
        em_service_type_t svc = em_service_type_ctrl);
};

#endif
