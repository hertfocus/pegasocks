#ifndef _CRM_CONFIG
#define _CRM_CONFIG

#include "crm_core.h"
#include <stdbool.h>
#include <json-c/json.h>

typedef struct crm_config_s crm_config_t;
typedef struct crm_server_config_s crm_server_config_t;
typedef struct crm_trojanserver_config_s crm_trojanserver_config_t;
typedef struct crm_trojanserver_ssl_s crm_trojanserver_ssl_t;
typedef struct crm_trojanserver_ws_s crm_trojanserver_ws_t;

struct crm_config_s {
	crm_server_config_t *servers;
	int servers_count;
	const char *local_address;
	int local_port;
	int timeout;
	int log_level;
	FILE *log_file;
};

struct crm_server_config_s {
	const char *server_address;
	const char *server_type;
	int server_port;
	char *password;
	void *extra; // type specific
};

struct crm_trojanserver_config_s {
	struct crm_trojanserver_ssl_s {
		const char *cert;
	} ssl;
	struct crm_trojanserver_ws_s {
		bool enabled;
		const char *path;
		const char *hostname;
		bool double_tls;
	} websocket;
	crm_ssl_ctx_t *ssl_ctx;
};

crm_config_t *crm_config_load(const char *config);
crm_server_config_t *crm_config_parse_servers(json_object *jobj);

void *crm_server_config_parse_extra(const char *server_type, json_object *jobj);
void crm_server_config_free_extra(const char *server_type, void *ptr);

crm_trojanserver_config_t *crm_trojanserver_config_parse(json_object *jobj);

crm_trojanserver_config_t *crm_trojanserver_config_new();
void crm_trojanserver_config_free(crm_trojanserver_config_t *tconf);

crm_config_t *crm_config_new();
void crm_config_free(crm_config_t *config);

crm_server_config_t *crm_servers_config_new(crm_size_t len);
void crm_servers_config_free(crm_server_config_t *servers,
			     crm_size_t servers_count);

#endif
