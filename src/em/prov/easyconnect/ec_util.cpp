#include <ctype.h>

#include "ec_util.h" 

void ec_util::init_frame(ec_frame_t *frame)
{
    memset(frame, 0, sizeof(ec_frame_t));
    frame->category = 0x04;
    frame->action = 0x09;
    frame->oui[0] = 0x50;
    frame->oui[1] = 0x6f;
    frame->oui[2] = 0x9a;
    frame->oui_type = DPP_OUI_TYPE;
    frame->crypto_suite = 0x01; // Section 3.3 (Currently only 0x01 is defined)
}

ec_attribute_t *ec_util::get_attrib(uint8_t *buff, uint16_t len, ec_attrib_id_t id)
{
    unsigned int total_len = 0;
    ec_attribute_t *attrib = (ec_attribute_t *)buff;

    while (total_len < len) {
        if (attrib->attr_id == id) {
            return attrib;
        }

        total_len += (get_ec_attr_size(attrib->length));
        attrib = (ec_attribute_t *)((uint8_t*)attrib + get_ec_attr_size(attrib->length));
    }

    return NULL;
}


uint8_t* ec_util::add_attrib(uint8_t *buff, ec_attrib_id_t id, uint16_t len, uint8_t *data)
{
    if (buff == NULL || data == NULL || len == 0) {
        fprintf(stderr, "Invalid input\n");
        return NULL;
    }
    memset(buff, 0, get_ec_attr_size(len));
    ec_attribute_t *attr = (ec_attribute_t *)buff;
    // EC attribute id and length are in host byte order according to the spec (8.1)
    attr->attr_id = id;
    attr->length = len;
    memcpy(attr->data, data, len);

    // Return the next attribute in the buffer
    return buff + get_ec_attr_size(len);
}


uint16_t ec_util::channel_to_frequency(unsigned int channel)
{
    uint16_t frequency = 0;

    if (channel <= 14) {
        frequency = 2412 + 5*(channel - 1);
    } else if ((channel >= 36) && (channel <= 64)) {
        frequency = 5180 + 5*(channel - 36);
    } else if ((channel >= 100) && (channel <= 140)) {
        frequency = 5500 + 5*(channel - 100);
    } else if ((channel >= 149) && (channel <= 165)) {
        frequency = 5745 + 5*(channel - 149);
    }

    return frequency;
}

uint16_t ec_util::freq_to_channel(unsigned int freq)
{
    unsigned int temp = 0;
    int sec_channel = -1;
    unsigned int op_class = 0;
    if (freq) {
        if (freq >= 2412 && freq <= 2472){
            if (sec_channel == 1)
                op_class = 83;
            else if (sec_channel == -1)
                op_class = 84;
            else
                op_class = 81;

            temp = ((freq - 2407) / 5);
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }

        /** In Japan, 100 MHz of spectrum from 4900 MHz to 5000 MHz
          can be used for both indoor and outdoor connection
         */
        if (freq >= 4900 && freq < 5000) {
            if ((freq - 4000) % 5)
                return 0;
            temp = (freq - 4000) / 5;
            op_class = 0; /* TODO */
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        if (freq == 2484) {
            op_class = 82; /* channel 14 */
            temp = 14;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 36..48 */
        if (freq >= 5180 && freq <= 5240) {
            if ((freq - 5000) % 5)
                return 0;

            if (sec_channel == 1)
                op_class = 116;
            else if (sec_channel == -1)
                op_class = 117;
            else
                op_class = 115;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 52..64 */
        if (freq >= 5260 && freq <= 5320) {
            if ((freq - 5000) % 5)
                return 0;

            if (sec_channel == 1)
                op_class = 119;
            else if (sec_channel == -1)
                op_class = 120;
            else
                op_class = 118;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 100..140 */
        if (freq >= 5000 && freq <= 5700) {
            if (sec_channel == 1)
                op_class = 122;
            else if (sec_channel == -1)
                op_class = 123;
            else
                op_class = 121;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 149..169 */
        if (freq >= 5745 && freq <= 5845) {
            if (sec_channel == 1)
                op_class = 126;
            else if (sec_channel == -1)
                op_class = 127;
            else if (freq <= 5805)
                op_class = 124;
            else
                op_class = 125;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }

#if HOSTAPD_VERSION >= 210 //2.10
        if (is_6ghz_freq(freq)) {
            if (freq == 5935) {
                temp = 2;
                op_class = 131;
            } else {
                temp = (freq - 5950) % 5;
                op_class = 131 + center_idx_to_bw_6ghz((freq - 5950) / 5);
            }
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
#endif
    }
    printf("error: No case for given Freq\n");
    return 0;
}

void ec_util::print_hex_dump(unsigned int length, uint8_t *buffer)
{
    int i;
    uint8_t buff[512] = {};
    const uint8_t * pc = (const uint8_t *)buffer;

    if ((pc == NULL) || (length <= 0)) {
        printf ("buffer NULL or BAD LENGTH = %d :\n", length);
        return;
    }

    for (i = 0; i < length; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }

        printf (" %02x", pc[i]);

        if (!isprint(pc[i]))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    printf ("  %s\n", buff);
}

bool ec_util::validate_frame(ec_frame_t *frame, ec_frame_type_t type)
{
    if ((frame->category != 0x04) 
            || (frame->action != 0x09)
            || (frame->oui[0] != 0x50)
            || (frame->oui[1] != 0x6f)
            || (frame->oui[2] != 0x9a)
            || (frame->oui_type != DPP_OUI_TYPE)
            || (frame->crypto_suite != 0x01)
            || (frame->frame_type != type)) {
        return false;
    }

    return true;
}

void ec_util::print_bignum (BIGNUM *bn)
{
    unsigned char *buf;
    int len;

    len = BN_num_bytes(bn);
    if ((buf = (unsigned char *)malloc(len)) == NULL) {
        printf("Could not print bignum\n");
        return;
    }
    BN_bn2bin(bn, buf);
    print_hex_dump(len, buf);
    free(buf);
}

void ec_util::print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point)
{
    BIGNUM *x = NULL, *y = NULL;

    if ((x = BN_new()) == NULL) {
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;
    }

    if ((y = BN_new()) == NULL) {
        BN_free(x);
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;
    }

    if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bnctx) == 0) {
        BN_free(y);
        BN_free(x);
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;

    }

    printf("POINT.x:\n");
    print_bignum(x);
    printf("POINT.y:\n");
    print_bignum(y);

    BN_free(y);
    BN_free(x);
}