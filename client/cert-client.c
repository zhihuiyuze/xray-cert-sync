// client.c
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include <unistd.h>
#include <json-c/json.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <sys/stat.h>

#define CHECK_INTERVAL_SECONDS 3600

char SERVER_URL[256];
char OUTPUT_CERT[256];
char OUTPUT_KEY[256];
char CLIENT_CERT[256];
char CLIENT_KEY[256];
char CA_CERT[256];
char XRAY_RELOAD_CMD[512];

size_t write_file(void *ptr, size_t size, size_t nmemb, FILE *stream) {
  return fwrite(ptr, size, nmemb, stream);
}

int load_config() {
  FILE *f = fopen("client-config.json", "r");
  if (!f) {
    perror("Failed to open config");
    return 1;
  }
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  rewind(f);
  char *data = malloc(len + 1);
  if (!data) {
    fclose(f);
    fprintf(stderr, "Failed to allocate memory for config data\n");
    return 1;
  }
  size_t read_bytes = fread(data, 1, len, f);
  if (read_bytes != len) {
    fclose(f);
    free(data);
    fprintf(stderr, "Failed to read entire config file\n");
    return 1;
  }
  data[len] = '\0';
  fclose(f);

  struct json_object *parsed = json_tokener_parse(data);
  free(data);
  if (!parsed) {
    fprintf(stderr, "Failed to parse config\n");
    return 1;
  }

  strcpy(SERVER_URL, json_object_get_string(json_object_object_get(parsed, "server_url")));
  strcpy(OUTPUT_CERT, json_object_get_string(json_object_object_get(parsed, "output_cert")));
  strcpy(OUTPUT_KEY, json_object_get_string(json_object_object_get(parsed, "output_key")));
  strcpy(CLIENT_CERT, json_object_get_string(json_object_object_get(parsed, "client_cert")));
  strcpy(CLIENT_KEY, json_object_get_string(json_object_object_get(parsed, "client_key")));
  strcpy(CA_CERT, json_object_get_string(json_object_object_get(parsed, "ca_cert")));
  strcpy(XRAY_RELOAD_CMD, json_object_get_string(json_object_object_get(parsed, "reload_command")));
  json_object_put(parsed);
  return 0;
}

int files_are_equal(const char *path1, const char *path2) {
  struct stat s1, s2;
  if (stat(path1, &s1) != 0 || stat(path2, &s2) != 0) return 0;
  if (s1.st_size != s2.st_size) return 0;
  FILE *f1 = fopen(path1, "rb");
  FILE *f2 = fopen(path2, "rb");
  if (!f1 || !f2) return 0;
  int result = 1;
  char buf1[4096], buf2[4096];
  size_t n1, n2;
  while ((n1 = fread(buf1, 1, sizeof(buf1), f1)) > 0 && (n2 = fread(buf2, 1, sizeof(buf2), f2)) > 0) {
    if (n1 != n2 || memcmp(buf1, buf2, n1) != 0) {
      result = 0;
      break;
    }
  }
  fclose(f1);
  fclose(f2);
  return result;
}

int download(const char *endpoint, const char *outfile) {
  CURL *curl = curl_easy_init();
  if (!curl) {
    fprintf(stderr, "[!] curl_easy_init failed\n");
    return 1;
  }

  char tmpfile[512];
  snprintf(tmpfile, sizeof(tmpfile), "%s.tmp", outfile);
  FILE *fp = fopen(tmpfile, "wb");
  if (!fp) {
    perror("[!] fopen failed");
    curl_easy_cleanup(curl);
    return 2;
  }

  char url[512];
  snprintf(url, sizeof(url), "%s/%s", SERVER_URL, endpoint);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_SSLCERT, CLIENT_CERT);
  curl_easy_setopt(curl, CURLOPT_SSLKEY, CLIENT_KEY);
  curl_easy_setopt(curl, CURLOPT_CAINFO, CA_CERT);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

  CURLcode res = curl_easy_perform(curl);
  fclose(fp);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) {
    fprintf(stderr, "[!] curl_easy_perform failed: %s\n", curl_easy_strerror(res));
    remove(tmpfile);
    return 3;
  }

  if (!files_are_equal(outfile, tmpfile)) {
    rename(tmpfile, outfile);
    return 0; // changed
  } else {
    remove(tmpfile);
    return 10; // not changed
  }
}

int main() {
  if (load_config() != 0) return 1;

  while (1) {
    int changed = 0;
    int cert_result = download("cert", OUTPUT_CERT);
    if (cert_result == 0) changed = 1;
    else if (cert_result == 3) fprintf(stderr, "[!] Failed to download cert\n");

    int key_result = download("key", OUTPUT_KEY);
    if (key_result == 0) changed = 1;
    else if (key_result == 3) fprintf(stderr, "[!] Failed to download key\n");

    if (changed) {
      printf("[+] Certificates updated, restarting xray...\n");
      system(XRAY_RELOAD_CMD);
    } else {
      printf("[-] No updates, xray not restarted.\n");
    }

    sleep(CHECK_INTERVAL_SECONDS);
  }

  return 0;
}