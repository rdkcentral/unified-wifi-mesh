/**
 * Abstract interface for private vendor TLV handlers.
 *
 * Each handler declares which attr_id it owns (handles()) and
 * implements the actual parsing (process()). The strong override of
 * em_vendor_t::handle_vendor_tlv_ext() iterates a static list of
 * registered handlers and dispatches to the first matching one.
 *
 * Adding a new private attr_id = adding a new subclass here +
 * one entry in the handlers[] array in vendor_sta_ctrl.cpp.
 * No other files need to change.
 */

#ifndef EM_VENDOR_TLV_HANDLER_H
#define EM_VENDOR_TLV_HANDLER_H

class dm_easy_mesh_t;

class em_vendor_tlv_handler_t {
public:
    // Returns true if this handler owns the given attr_id.
    virtual bool handles(unsigned char attr_id) const = 0;

    // Processes the full vendor-specific TLV value (OUI + num + attr_id + payload).
    // Returns number of objects updated, 0 if nothing to do, -1 on error.
    virtual int  process(const unsigned char *tlv_value,
                         unsigned int         tlv_len,
                         dm_easy_mesh_t      *dm) = 0;

    virtual ~em_vendor_tlv_handler_t() = default;
};

#endif // EM_VENDOR_TLV_HANDLER_H
