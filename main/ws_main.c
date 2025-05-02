#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <unistd.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include <freertos/FreeRTOS.h>
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include <esp_system.h>
#include "mbedtls/sha1.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform.h"
#include "driver/gpio.h"
#include "sdkconfig.h"
#include <inttypes.h>

/* Pin and port definitions */
#define TXD_PIN (GPIO_NUM_17)
#define RXD_PIN (GPIO_NUM_16)
#define UART_NUM UART_NUM_2

#define PORT 80
#define MAX_CONN 5
#define MAX_BUFFER_SIZE 1024

/* WiFi configuration */
#define AP_SSID "AndroidAP"
#define AP_PSSWD "saloni@123"

/* WebSocket constants */
const char *GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
static const char *TAG = "Websocket Server";
char base64_output[50] = {0};
QueueHandle_t sha1_queue;

/* Function declarations */
static void wifi_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
void uart_init(void);
void wifi_connection(void);
void sha1_example(const char *input_data);
void printBinaryDataHex(const char* data, size_t length);
void client_task(void *client_socket);
void socket_task(void *pvParameters);

/* Initialize UART */
void uart_init(void) {
    const uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_APB
    };

    uart_param_config(UART_NUM, &uart_config);
    uart_set_pin(UART_NUM, TXD_PIN, RXD_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    uart_driver_install(UART_NUM, 1024 * 2, 0, 0, NULL, 0);
}

/* Initialize WiFi connection */
void wifi_connection(void) {
    nvs_flash_init();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t wifi_initiation = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wifi_initiation);

    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL);

    wifi_config_t wifi_configuration = {
        .sta = {
            .ssid = AP_SSID,
            .password = AP_PSSWD,
            .failure_retry_cnt = 3
        }
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_configuration));
    ESP_ERROR_CHECK(esp_wifi_start());

    vTaskDelay(200 / portTICK_PERIOD_MS);
    esp_wifi_connect();
}

/* WiFi event handler */
static void wifi_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    switch (event_id) {
        case WIFI_EVENT_STA_START:
            ESP_LOGI(TAG, "WiFi connecting ...");
            break;
        case WIFI_EVENT_STA_CONNECTED:
            ESP_LOGI(TAG, "WiFi connected ...");
            break;
        case WIFI_EVENT_STA_DISCONNECTED: {
            wifi_event_sta_disconnected_t *disconnected = (wifi_event_sta_disconnected_t *)event_data;
            ESP_LOGW(TAG, "WiFi lost connection. Reason: %d", disconnected->reason);
            break;
        }
        case IP_EVENT_STA_GOT_IP:
            ESP_LOGI(TAG, "WiFi got IP ...");
            break;
        default:
            break;
    }
}

/* Generate SHA1 hash and encode in base64 */
void sha1_example(const char *input_data) {
    mbedtls_sha1_context sha1_ctx;
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts(&sha1_ctx);
    mbedtls_sha1_update(&sha1_ctx, (const unsigned char *)input_data, strlen(input_data));

    unsigned char sha1_output[20];
    mbedtls_sha1_finish(&sha1_ctx, sha1_output);

    printf("Input data: %s\n", input_data);

    size_t base64_output_len;
    mbedtls_base64_encode((unsigned char *)base64_output, sizeof(base64_output), &base64_output_len,
                          sha1_output, sizeof(sha1_output));
    printf("Base64 encoded SHA-1 hash: %s\n", base64_output);
}

/* Debug function to print binary data in hex format */
void printBinaryDataHex(const char* data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("0x%02X ", (unsigned char)data[i]);
    }
    printf("\n");
}

/* Client connection handler task */
void client_task(void *client_socket) {
    int clientSocket = *((int *)client_socket);
    char *websocket_request = malloc(1024);
    bool handshake_complete = false;
    int total_bytes_received = 0;

    while (true) {
        vTaskDelay(25 / portTICK_PERIOD_MS);
        
        if (handshake_complete == false) {
            ESP_LOGI(TAG, "Loop started");
            int bytes_received = recv(clientSocket, websocket_request + total_bytes_received, 1024 + total_bytes_received, 0);
            
            if (bytes_received < 0) {
                ESP_LOGE(TAG, "Error receiving data");
            } else if (bytes_received == 0) {
                ESP_LOGI(TAG, "No data received");
            }
            
            total_bytes_received += bytes_received;
            ESP_LOGI(TAG, "Received %d bytes:\n%.*s", bytes_received, bytes_received, websocket_request);
            
            if (strstr(websocket_request, "Upgrade: websocket") && strstr(websocket_request, "Connection: Upgrade")) {
                ESP_LOGI(TAG, "It is a websocket request!");
            } else {
                ESP_LOGI(TAG, "Not a websocket request...");
            }

            const char* key_header = "Sec-WebSocket-Key";
            const char* header_line = strstr(websocket_request, key_header);

            if (header_line == NULL) {
                ESP_LOGE(TAG, "ERROR finding headerLine");
            }

            const char* colon = strchr(header_line, ':');
            if (colon == NULL) {
                ESP_LOGE(TAG, "Colon not found in headerLine");
            }

            const char* key_value = colon + 1;
            while (*key_value == ' ' || *key_value == '\t') {
                key_value++;
            }

            const int value_length = strcspn(key_value, "\r\n");
            char* key_with_guid = malloc(value_length + strlen(GUID) + 1);
            strncpy(key_with_guid, key_value, value_length);
            ESP_LOGI(TAG, "Original key: %s", key_with_guid);
            strcat(key_with_guid, GUID);
            key_with_guid[value_length + strlen(GUID)] = '\0';
            ESP_LOGI(TAG, "Key with GUID is: %s", key_with_guid);
            sha1_example(key_with_guid);

            char* handshake_response = "HTTP/1.1 101 Switching Protocols\r\n"
                    "Server: ESP-WebSocketsServer\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Version: 13\r\n"
                    "Sec-WebSocket-Accept: ";

            size_t response_len = strlen(handshake_response) + strlen(base64_output) + 5;
            char *response_buffer = malloc(response_len + 15);
            if (response_buffer == NULL) {
                ESP_LOGE(TAG, "Failed to allocate memory for response_buffer");
                return;
            }

            snprintf(response_buffer, response_len, "%s%s\r\n\r\n", handshake_response, base64_output);

            printf("Before sending\n");
            ESP_LOGI(TAG, "%s", response_buffer);
            send(clientSocket, response_buffer, response_len, 0);

            free(response_buffer);
            free(key_with_guid);
            free(websocket_request);
            ESP_LOGI(TAG, "Buffers freed");
            printf("Handshake done!");
            handshake_complete = true;
        }
        else {
            // Allocate memory for binary data buffer
            uint8_t* data_buffer = (uint8_t*)malloc(17 * sizeof(uint8_t));

            if (data_buffer == NULL) {
                ESP_LOGE(TAG, "Memory allocation failed");
            }

            // Receive binary data
            int data_bytes_received = recv(clientSocket, data_buffer, 17, 0);

            if (data_bytes_received > 0) {
                ESP_LOGI(TAG, "Data received");
                uint8_t* hex_data_buffer = (uint8_t*)malloc(17 * sizeof(uint8_t));  // Raw data from client
                
                for (int i = 0; i < data_bytes_received; i++) {
                    hex_data_buffer[i] = data_buffer[i];  // Storing data
                }
                
                printf("Data received from client: ");
                for (int i = 0; i < data_bytes_received; i++) {
                    printf("0x%02x ", (unsigned int)hex_data_buffer[i]);
                }
                printf("\n");

                // Extract mask bytes
                char mask_bytes[4] = {
                    hex_data_buffer[2], 
                    hex_data_buffer[3], 
                    hex_data_buffer[4], 
                    hex_data_buffer[5]
                };

                // Extract client data
                uint8_t* client_data = (uint8_t*)malloc(12 * sizeof(uint8_t));
                if (client_data == NULL) {
                    ESP_LOGE(TAG, "Memory allocation failed");
                }

                int client_data_index = 0;
                for (int frame_index = 6; frame_index < 17; frame_index++) {
                    client_data[client_data_index] = hex_data_buffer[frame_index];
                    client_data_index++;
                }
                ESP_LOGI(TAG, "Client data stored");

                // Debug output
                printf("Mask bytes: \n");
                for (int i = 0; i < 4; i++) {
                    printf("0x%02x ", (unsigned int)mask_bytes[i]);
                }
                printf("\n");
                
                printf("Client data bytes: \n");
                for (int i = 0; i < 11; i++) {
                    printf("0x%02x ", (unsigned int)client_data[i]);
                }
                printf("\n");

                // Decode data from client
                char* decoded_data = (char*)malloc(12 * sizeof(char));
                
                for (int j = 0; j < 11; j++) {
                    decoded_data[j] = mask_bytes[j % 4] ^ client_data[j];
                }
                
                printf("%d", client_data_index);
                decoded_data[11] = '\0';
                ESP_LOGI(TAG, "Decoded data from client is: ");
                
                for (int m = 0; m < 11; m++) {
                    printf("%c", decoded_data[m]);
                }
                printf("\n");

                // Create JSON response
                cJSON *json_root = cJSON_CreateObject();
                cJSON_AddStringToObject(json_root, "Status", decoded_data);
                
                char *json_string = cJSON_Print(json_root);
                
                char *newStr = (char *)malloc(strlen(json_string) + 2);
                strcpy(newStr, json_string);
                newStr[strlen(json_string)] = '*';
                newStr[strlen(json_string) + 1] = '\0';
                
                uart_write_bytes(UART_NUM, newStr, strlen(newStr));
                ESP_LOGI(TAG, "Modified json string is %s \n", newStr);
                
                free(json_string);
                free(newStr);
                
                vTaskDelay(pdMS_TO_TICKS(1000));
                
                cJSON_Delete(json_root);

                // Free resources
                free(decoded_data);
                free(client_data);
                free(hex_data_buffer);
                ESP_LOGD(TAG, "hex_buffer freed");
            } 
            else if (data_bytes_received == 0) {
                ESP_LOGI(TAG, "No data frame received");
            } 
            else {
                vTaskDelay(100 / portTICK_PERIOD_MS);
                ESP_LOGE(TAG, "Error receiving data: %d", data_bytes_received);
            }

            free(data_buffer);
            ESP_LOGI(TAG, "Data_buffer freed");
        }
    }
}

/* Socket server task */
void socket_task(void *pvParameters) {
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrLen = sizeof(clientAddr);

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        ESP_LOGE(TAG, "Socket creation failed");
        vTaskDelete(NULL);
        return;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(PORT);

    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        ESP_LOGE(TAG, "Socket binding failed");
        close(serverSocket);
        vTaskDelete(NULL);
        return;
    }

    if (listen(serverSocket, MAX_CONN) < 0) {
        ESP_LOGE(TAG, "Listen failed");
        close(serverSocket);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Websocket is listening.....");

    while (true) {
        clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &addrLen);
        if (clientSocket < 0) {
            ESP_LOGE(TAG, "Unable to accept connection");
            continue;
        }

        ESP_LOGI(TAG, "Connection Accepted");
        xTaskCreate(client_task, "client_task", 4096, &clientSocket, configMAX_PRIORITIES, NULL);
    }

    close(serverSocket);
    vTaskDelete(NULL);
}

/* Main application entry point */
void app_main(void) {
    uart_init();
    wifi_connection();
    
    mbedtls_platform_setup(NULL);
    vTaskDelay(1500 / portTICK_PERIOD_MS);
    xTaskCreate(socket_task, "socket_task", 4096, NULL, configMAX_PRIORITIES, NULL);
    mbedtls_platform_teardown(NULL);
}