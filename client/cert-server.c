// server.c
#define _XOPEN_SOURCE
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <microhttpd.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include <signal.h>
#include <stdbool.h>

#define PORT 8449
#define CHECK_INTERVAL_SECONDS 3600  // Check every 1 hour

char CERT_FILE[512];
char KEY_FILE[512];
char TLS_CERT_FILE[512];
char TLS_KEY_FILE[512];
char CLIENT_CERT_FILE[512];
char RENEW_COMMAND[1024];

#define RENEW_THRESHOLD_DAYS 7

volatile bool keep_running = true;

void handle_signal(int sig) {
  keep_running = false;
}

void load_config() {
  FILE *f = fopen("server-config.json", "r");
  if (!f) {
    perror("Failed to open config");
    exit(1);
  }
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  rewind(f);
  char *data = malloc(len + 1);
  fread(data, 1, len, f);
  data[len] = '\0';
  fclose(f);

  struct json_object *parsed = json_tokener_parse(data);
  free(data);
  if (!parsed) {
    fprintf(stderr, "Failed to parse config\n");
    exit(1);
  }

  strcpy(CERT_FILE, json_object_get_string(json_object_object_get(parsed, "xray_cert")));
  strcpy(KEY_FILE, json_object_get_string(json_object_object_get(parsed, "xray_key")));
  strcpy(TLS_CERT_FILE, json_object_get_string(json_object_object_get(parsed, "tls_cert")));
  strcpy(TLS_KEY_FILE, json_object_get_string(json_object_object_get(parsed, "tls_key")));
  strcpy(CLIENT_CERT_FILE, json_object_get_string(json_object_object_get(parsed, "ca_cert")));
  strcpy(RENEW_COMMAND, json_object_get_string(json_object_object_get(parsed, "renew_command")));
  json_object_put(parsed);
}

int check_cert_expiry(const char *cert_path) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd),
           "openssl x509 -enddate -noout -in %s | cut -d= -f2", cert_path);
  FILE *fp = popen(cmd, "r");
  if (!fp) return -1;
  char buffer[256];
  if (!fgets(buffer, sizeof(buffer), fp)) {
    pclose(fp);
    return -1;
  }
  pclose(fp);
  struct tm tm;
  strptime(buffer, "%b %d %H:%M:%S %Y %Z", &tm);
  time_t expiry = mktime(&tm);
  time_t now = time(NULL);
  double days_left = difftime(expiry, now) / (60 * 60 * 24);
  return (days_left < RENEW_THRESHOLD_DAYS);
}

void check_and_renew_cert() {
  if (check_cert_expiry(CERT_FILE)) {
    printf("[!] Xray certificate expiring soon, renewing...\n");
    system(RENEW_COMMAND);
    printf("[+] Renew command issued.\n");
  }
}

enum MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                         const char *url, const char *method,
                         const char *version, const char *upload_data,
                         size_t *upload_data_size, void **con_cls) {
  if (strcmp(method, "GET") != 0)
    return MHD_NO;

  const char *filepath = NULL;
  if (strcmp(url, "/cert") == 0) {
    filepath = CERT_FILE;
  } else if (strcmp(url, "/key") == 0) {
    filepath = KEY_FILE;
  } else {
    return MHD_NO;
  }

  FILE *f = fopen(filepath, "rb");
  if (!f) return MHD_NO;
  fseek(f, 0, SEEK_END);
  size_t len = ftell(f);
  rewind(f);
  char *buffer = malloc(len);
  fread(buffer, 1, len, f);
  fclose(f);

  struct MHD_Response *response = MHD_create_response_from_buffer(len, buffer, MHD_RESPMEM_MUST_FREE);
  int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);
  return ret;
}

int main() {
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  load_config();

  FILE *fcert = fopen(TLS_CERT_FILE, "rb");
  FILE *fkey = fopen(TLS_KEY_FILE, "rb");
  if (!fcert || !fkey) {
    perror("Failed to open TLS cert/key file");
    return 1;
  }

  fseek(fcert, 0, SEEK_END);
  size_t cert_len = ftell(fcert);
  rewind(fcert);
  char *cert_mem = malloc(cert_len + 1);
  fread(cert_mem, 1, cert_len, fcert);
  cert_mem[cert_len] = '\0';
  fclose(fcert);

  fseek(fkey, 0, SEEK_END);
  size_t key_len = ftell(fkey);
  rewind(fkey);
  char *key_mem = malloc(key_len + 1);
  fread(key_mem, 1, key_len, fkey);
  key_mem[key_len] = '\0';
  fclose(fkey);

  struct MHD_Daemon *daemon;
  daemon = MHD_start_daemon(MHD_USE_SSL | MHD_USE_SELECT_INTERNALLY,
                            PORT, NULL, NULL,
                            &answer_to_connection, NULL,
                            MHD_OPTION_HTTPS_MEM_KEY, key_mem,
                            MHD_OPTION_HTTPS_MEM_CERT, cert_mem,
                            MHD_OPTION_HTTPS_MEM_TRUST, CLIENT_CERT_FILE,
                            MHD_OPTION_END);
  if (NULL == daemon) {
    perror("MHD_start_daemon failed");
    return 1;
  }

  printf("[+] HTTPS server running on port %d\n", PORT);

  while (keep_running) {
    check_and_renew_cert();
    sleep(CHECK_INTERVAL_SECONDS);
  }

  printf("[-] Shutting down...\n");
  MHD_stop_daemon(daemon);
  free(cert_mem);
  free(key_mem);
  return 0;
}