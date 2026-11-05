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

    // Controller: the ACL state the request changed and stored (pre_process_orch_op), kept until
    // the agent's ACK so the STAs it refuses (Error Code TLVs) get their previous state back
    em_acl_undo_t m_acl_undo;
    em_2xlong_string_t m_acl_bss_key;
    bool m_acl_undo_valid;
};

#endif
