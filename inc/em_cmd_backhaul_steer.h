#ifndef EM_CMD_BACKHAUL_STEER_H
#define EM_CMD_BACKHAUL_STEER_H

#include "em_cmd.h"

class em_cmd_backhaul_steer_t : public em_cmd_t {

public:

    /**!
     * @brief Constructs a backhaul steering command.
     *
     * @param[in] params The backhaul steering parameters (al_mac, sta_mac, target_bssid, op_class, channel).
     * @param[in] svc    Service type (controller or agent). Defaults to controller.
     */
    em_cmd_backhaul_steer_t(em_cmd_backhaul_steer_params_t params,
                            em_service_type_t svc = em_service_type_ctrl);
};

#endif
