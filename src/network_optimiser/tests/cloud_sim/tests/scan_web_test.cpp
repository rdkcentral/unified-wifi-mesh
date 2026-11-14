#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include "web.h"

class scan_web_test_t : public web_t {
public:
    unsigned int calls = 0;
    optimizer_event_type_t last_type = optimizer_event_type_unknown;
    std::string last_request;
    const char *response = "{\"Status\":\"Complete\",\"Data\":{\"Status\":\"Success\"}}";

    const char *device_request(optimizer_event_t *req, optimizer_event_t *) override
    {
        ++calls;
        last_type = req->get_type();
        last_request = static_cast<const char *>(req->get_data());
        return response;
    }

    std::string post(const char *route, const std::string &body)
    {
        int sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
        std::string request = "POST " + std::string(route) +
            " HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body;
        handle_post(sockets[0], route, &request[0]);
        shutdown(sockets[0], SHUT_WR);
        std::string result;
        char buffer[1024];
        ssize_t size;
        while ((size = read(sockets[1], buffer, sizeof(buffer))) > 0) {
            result.append(buffer, static_cast<size_t>(size));
        }
        assert(size == 0);
        close(sockets[0]);
        close(sockets[1]);
        const size_t start = result.find("\r\n\r\n");
        assert(start != std::string::npos);
        return result.substr(start + 4);
    }

    void forwards(const char *route, optimizer_event_type_t type, const std::string &body)
    {
        const unsigned int before = calls;
        assert(post(route, body) == response);
        assert(calls == before + 1);
        assert(last_type == type);
        cJSON *event = cJSON_Parse(last_request.c_str());
        cJSON *original = cJSON_Parse(body.c_str());
        assert(event != NULL && original != NULL);
        const char *name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(event, "Request"));
        assert(name != NULL && strcmp(name, route + 1) == 0);
        assert(cJSON_Compare(cJSON_GetObjectItemCaseSensitive(event, "Data"), original, true));
        assert(optimizer_event_t::optimizer_string_2_event_type(name, strlen(name)) == type);
        cJSON_Delete(original);
        cJSON_Delete(event);
    }

    void rejects(const char *route, const std::string &body)
    {
        const unsigned int before = calls;
        assert(post(route, body) == "{\"Status\":\"Error_Invalid_Input\"}");
        assert(calls == before);
    }
};

int main()
{
    scan_web_test_t web;
    web.init("");
    const std::string full = "{\"Band\":\"5GHz\",\"Input\":{\"DwellTime\":100,\"DFSDwellTime\":250}}";
    web.forwards("/FullScan", optimizer_event_type_full_scan, full);
    web.forwards("/FullScan", optimizer_event_type_full_scan,
        "{\"Band\":\"2.4GHz\",\"Input\":{\"DwellTime\":0,\"DFSDwellTime\":4294967295,"
        "\"HomeTime\":0,\"SSID\":\"a \\\"quoted\\\" SSID\"}}");
    web.forwards("/ChannelScan", optimizer_event_type_channel_scan,
        "{\"Input\":{\"DwellTime\":50,\"DFSDwellTime\":100,\"HomeTime\":50,"
        "\"OpClass\":[{\"OperatingClass\":81,\"Channel\":[{\"Channel\":1},{\"Channel\":6}]},"
        "{\"OperatingClass\":115,\"Channel\":[{\"Channel\":36}]}]}}");
    web.forwards("/ChannelScan", optimizer_event_type_channel_scan,
        "{\"Input\":{\"DwellTime\":50,\"DFSDwellTime\":100,\"OpClass\":[]}}");
    web.forwards("/SetSSID", optimizer_event_type_set_ssid, "{\"SSID\":\"unchanged\"}");

    for (const char *body : {
        "not json", "null", "[]", "{}",
        "{\"Band\":\"5GHz\",\"Input\":{\"DwellTime\":100}}",
        "{\"Band\":\"5GHz\",\"Input\":{\"DwellTime\":\"100\",\"DFSDwellTime\":250}}",
        "{\"Band\":\"5GHz\",\"Input\":{\"DwellTime\":-1,\"DFSDwellTime\":250}}",
        "{\"Band\":\"5GHz\",\"Input\":{\"DwellTime\":0.5,\"DFSDwellTime\":250}}",
        "{\"Band\":\"5GHz\",\"Input\":{\"DwellTime\":4294967296,\"DFSDwellTime\":250}}",
        "{\"Band\":\"5GHz\",\"Input\":{\"DwellTime\":1e999,\"DFSDwellTime\":250}}",
        "{\"Band\":\"bad\",\"Input\":{\"DwellTime\":100,\"DFSDwellTime\":250}}",
        "{\"Band\":\"5GHz\",\"Input\":{\"DwellTime\":100,\"DFSDwellTime\":250,\"HomeTime\":null}}",
        "{\"Band\":\"5GHz\",\"Input\":{\"DwellTime\":100,\"DFSDwellTime\":250,\"SSID\":3}}"
    }) {
        web.rejects("/FullScan", body);
    }
    for (const char *op_class : {
        "null", "{}", "[{}]",
        "[{\"OperatingClass\":256,\"Channel\":[]}]",
        "[{\"OperatingClass\":81,\"Channel\":[1]}]",
        "[{\"OperatingClass\":81,\"Channel\":[{\"Channel\":256}]}]",
        "[{\"OperatingClass\":81,\"Channel\":[{\"Channel\":-1}]}]",
        "[{\"OperatingClass\":81,\"Channel\":[{\"Channel\":1.5}]}]"
    }) {
        web.rejects("/ChannelScan",
            "{\"Input\":{\"DwellTime\":100,\"DFSDwellTime\":250,\"OpClass\":" +
            std::string(op_class) + "}}");
    }
    web.rejects("/UnknownScan", full);
    web.response = NULL;
    assert(web.post("/FullScan", full) == "{\"Status\":\"Error_Other\"}");
    web.response = "{\"Status\":\"Failed\"}";
    assert(web.post("/FullScan", full) == web.response);
    puts("Scan web routing, validation, serialization and response tests passed.");
}
