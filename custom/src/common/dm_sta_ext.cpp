/**
 * Private extension implementation for dm_sta_t.
 *
 * Overrides the constructors and destructor from the public repo's dm_sta.cpp
 * so that m_sta_ext (dm_sta_ext_t) is properly allocated and freed.
 */

#include "dm_sta.h"
#include "custom/inc/dm_sta_ext.h"
#include <cjson/cJSON.h>

// ─── dm_sta_t constructor / destructor overrides ─────────────────────────────

dm_sta_t::dm_sta_t()
    : m_sta_ext(new dm_sta_ext_t())
{
    memset(&m_sta_info, 0, sizeof(em_sta_info_t));
}

dm_sta_t::dm_sta_t(em_sta_info_t *sta)
    : m_sta_ext(new dm_sta_ext_t())
{
    memcpy(&m_sta_info, sta, sizeof(em_sta_info_t));
}

dm_sta_t::dm_sta_t(const dm_sta_t& sta)
    : m_sta_ext(sta.m_sta_ext ? new dm_sta_ext_t(*sta.m_sta_ext) : nullptr)
{
    memcpy(&m_sta_info, &sta.m_sta_info, sizeof(em_sta_info_t));
}

dm_sta_t::~dm_sta_t()
{
    delete m_sta_ext;
    m_sta_ext = nullptr;
}

// ─── dm_sta_ext_t::decode_from_json ──────────────────────────────────────────
//
// Parses vendor-private JSON fields from the same cJSON object that
// dm_sta_t::decode() used for public fields.
//
void dm_sta_ext_t::decode_from_json(dm_sta_t *sta, const cJSON *obj)
{
    if (!sta->get_priv()) {
        sta->set_priv(new dm_sta_ext_t());
    }
    dm_sta_ext_t *ext = sta->get_priv();

    cJSON *tmp;

    if ((tmp = cJSON_GetObjectItem(obj, "CustomScore")) != NULL) {
        ext->custom_score = static_cast<unsigned int>(tmp->valueint);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "IsManagedClient")) != NULL) {
        ext->is_managed_client = static_cast<bool>(tmp->valueint);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "CustomTag")) != NULL) {
        const char *tag = cJSON_GetStringValue(tmp);
        if (tag) ext->custom_tag = tag;
    }
}

// Strong override of the weak no-op in dm_sta.cpp — delegates to the class.
extern "C" void custom_decode_sta(dm_sta_t *sta, const cJSON *obj)
{
    dm_sta_ext_t::decode_from_json(sta, obj);
}
