#include <WiFi.h>
#include <esp_now.h>
#include <Adafruit_NeoPixel.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>

#define BUTTON_PIN 7
#define RSA_KEY_LENGTH 3072
#define RSA_EXPONENT 65537
#define DEFAULT 0
#define BROADCASTING 1
#define KEY_EXCHANGE 2
#define CHALLENGING 3
#define SEND_SESSION_KEY 4
#define MAX_DATA_SIZE 211
#define MAX_MESSAGES 10
#define MAX_PARTS 10
#define PMK "#ArtworkTracking"

Adafruit_NeoPixel pixels(1, 48, NEO_GRB + NEO_KHZ800);
int STATE = DEFAULT;
int time_elapsed = 0;
mbedtls_rsa_context rsa;  // Initialize a global RSA context
uint8_t clientMAC[6];
String pem_peer;  // public key of peer
String challengePhrase;
const uint8_t broadcastAddress[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
// Populate whitelist with allowed mac addresses
const uint8_t allowedMacAddresses[][6] = {
  { 0xf4, 0x12, 0xfa, 0xe6, 0x56, 0xe4 },
};

typedef struct message {     // Structure for long messages
  char id[37];               // Unique message id
  byte count;                // Number of packets sent yet
  byte total;                // Total number of packages to be sent
  char data[MAX_DATA_SIZE];  // Data
} message;

struct MessagePart {
  int index;
  char data[MAX_DATA_SIZE];
};

struct MessageRec {
  char id[37];
  MessagePart parts[MAX_PARTS];
  int total;
  int received;
};
MessageRec messages[MAX_MESSAGES];


typedef struct measure {  // Structure for sensor data
  int temperature;
  int humidity;
  int temperatureAlarm;
  int humidityAlarm;
} measure;


void setup() {
  // General initialization
  Serial.begin(115200);
  pixels.begin();
  pixels.setPixelColor(0, pixels.Color(17, 17, 17));
  pixels.show();
  pinMode(BUTTON_PIN, INPUT);

  // Setup ESP-NOW
  WiFi.mode(WIFI_STA);
  if (esp_now_init() == ESP_OK) {
    uint8_t pmk[16];
    hexStringToByteArray(PMK, pmk, 16);
    esp_now_set_pmk(pmk);                         // Change the PMK for an extra layer of security
    esp_now_register_recv_cb(receiveSensorData);  // Register the default recieve callback
    esp_now_register_send_cb(sendHandler);        // Register the default send callback
  } else {
    Serial.println("ESP-NOW Init Failed. Retry...");
    delay(3000);
    ESP.restart();
  }

  pixels.setPixelColor(0, pixels.Color(0, 17, 0));  // Set the led to green
  pixels.show();
}

void loop() {
  if (STATE == BROADCASTING) {
    sendBroadcast();
  } else if (STATE == DEFAULT && digitalRead(BUTTON_PIN) == HIGH) {
    STATE = BROADCASTING;
    esp_now_register_recv_cb(receiveOnboardRequest);  // Register the onboarding callback
    esp_now_unregister_send_cb();                     // Unregister the send callback

    pixels.setPixelColor(0, pixels.Color(17, 17, 17));
    pixels.show();

    initializeRSAKey();  // RSA key pair generation. Can take up to 25s

    pixels.setPixelColor(0, pixels.Color(0, 0, 17));
    pixels.show();

    Serial.println("Sending Broadcast to " + formatMacAddress(broadcastAddress));
  }

  if (STATE != DEFAULT) {
    sleep(3);
    if (++time_elapsed >= 20) reset();  // Reset after 60 seconds (3s * 20)
  }
}


// Called when data is sent
void sendHandler(const uint8_t* macAddr, esp_now_send_status_t status) {
  if (status == ESP_NOW_SEND_FAIL) {
    Serial.println("Package sent to " + formatMacAddress(macAddr) + " FAILED ");
    pixels.setPixelColor(0, pixels.Color(17, 0, 0));
  } else {
    pixels.setPixelColor(0, pixels.Color(0, 17, 0));
  }
  pixels.show();
}

// Called when sensor data is received (default)
void receiveSensorData(const uint8_t* macAddr, const uint8_t* data, int dataLen) {
  if (!deviceAllowed(macAddr)) return;
  measure m;
  memcpy(&m, data, sizeof(m));

  if (m.temperature >= m.temperatureAlarm || m.humidity >= m.humidityAlarm || m.temperature > 250 || m.humidity > 250) {  // Check if alarm is triggered
    pixels.setPixelColor(0, pixels.Color(17, 0, 0));
    if (m.temperature > 250) m.temperature = -999;
    if (m.humidity > 250) m.humidity = -999;
  } else {
    pixels.setPixelColor(0, pixels.Color(0, 17, 0));
  }

  Serial.println("Temperature: " + (String)m.temperature + " °C");
  Serial.println("Humidity: " + (String)m.humidity + "%");
  pixels.show();
}

void sendBroadcast() {
  esp_now_peer_info_t peerInfo = {};                                          // Create peer
  memcpy(&peerInfo.peer_addr, broadcastAddress, 6);                           // Add mac adress of peer (in this case broadcast to everyone)
  if (!esp_now_is_peer_exist(broadcastAddress)) esp_now_add_peer(&peerInfo);  // Add the peer to the list

  // Send message
  const String message = "Artwork Tracking Onboarding";
  esp_err_t result = esp_now_send(broadcastAddress, (const uint8_t*)message.c_str(), message.length());

  if (result != ESP_OK) Serial.println("Broadcast Failed... Trying again.");
}

// Called when onboarding request is received
void receiveOnboardRequest(const uint8_t* macAddr, const uint8_t* data, int dataLen) {
  if (!deviceAllowed(macAddr)) return;
  for (int i = 0; i < 6; i++) clientMAC[i] = macAddr[i];
  Serial.println("Receiving Onboarding Request from " + formatMacAddress(macAddr));
  time_elapsed = 0;

  char buffer[dataLen + 1];  // Only allow a maximum of 250 characters in the message + a null terminating byte
  strncpy(buffer, (const char*)data, dataLen);
  buffer[dataLen] = 0;  // Make sure we are null terminated

  if (strcmp(buffer, "Onboarding Request") == 0) {
    esp_now_register_send_cb(sendHandler);
    sendPublicKey(macAddr);
  } else {
    Serial.println("Bad request from " + formatMacAddress(macAddr) + ".");
  }
}

void sendPublicKey(const uint8_t* macAddr) {
  STATE = KEY_EXCHANGE;
  Serial.println("Sending Public Key to " + formatMacAddress(macAddr));
  esp_now_register_recv_cb(receivePublicKey);  // Register the recieve callback

  esp_now_del_peer(broadcastAddress);                             // Remove broadcast since it is not necessary any more.
  esp_now_peer_info_t peerInfo = {};                              // Create peer
  memcpy(&peerInfo.peer_addr, macAddr, 6);                        // Add mac adress of peer (in this case broadcast to everyone)
  if (esp_now_is_peer_exist(macAddr)) esp_now_del_peer(macAddr);  // Remove if there is an old connection
  esp_now_add_peer(&peerInfo);                                    // Add the peer to the list

  sendLongMessage(exportPublicKey().c_str(), macAddr);
}

void receivePublicKey(const uint8_t* macAddr, const uint8_t* data, int dataLen) {
  if (!deviceAllowed(macAddr) || memcmp(clientMAC, macAddr, 6) != 0) return;  // Check if data comes from correct client

  Serial.println("Receiving Public Key from " + formatMacAddress(macAddr));
  String message = receiveLongMessage(macAddr, data, dataLen);

  if (!message.equals("")) {  // Message completely received.
    pem_peer = message;
    sendChallenge(macAddr);
  }
}

void sendChallenge(const uint8_t* macAddr) {
  STATE = CHALLENGING;
  esp_now_register_recv_cb(receiveChallengeResponse);  // Register the recieve callback
  Serial.println("Sending Challenge to " + formatMacAddress(macAddr) + " started.");
  challengePhrase = generateAESKey();
  sendLongMessage(encryptRSA(challengePhrase).c_str(), macAddr);
}

void receiveChallengeResponse(const uint8_t* macAddr, const uint8_t* data, int dataLen) {
  if (!deviceAllowed(macAddr) || memcmp(clientMAC, macAddr, 6) != 0) return;  // Check if data comes from correct client
  Serial.println("Receiving Challenge Response from " + formatMacAddress(macAddr) + " received");

  String message = receiveLongMessage(macAddr, data, dataLen);

  if (!message.equals("")) {  // Message completely received.
    if (decryptRSA(message).equals(challengePhrase)) {
      challengePhrase.clear();
      sendSessionKey(macAddr);
    } else {
      Serial.println("Challenge not passed. Abbord...");
      reset();
    }
  }
}

void sendSessionKey(const uint8_t* macAddr) {
  STATE = SEND_SESSION_KEY;
  esp_now_register_recv_cb(receiveSensorData);  // Register the recieve callback
  Serial.println("Sending Session Key to " + formatMacAddress(macAddr) + " started.");
  String sessionKey = generateAESKey();

  sendLongMessage(encryptRSA(sessionKey).c_str(), macAddr);

  if (esp_now_is_peer_exist(macAddr)) esp_now_del_peer(macAddr);
  uint8_t lmk[16];
  hexStringToByteArray(sessionKey, lmk, 16);
  esp_now_peer_info_t peerInfo = {};                                 // Create peer
  memcpy(&peerInfo.peer_addr, macAddr, 6);                           // Add mac adress of peer (in this case broadcast to everyone)
  memcpy(&peerInfo.lmk, lmk, 16);                                    // Add Local Master Key (LMK) of peer
  peerInfo.encrypt = true;                                           // Enable encryption
  if (!esp_now_is_peer_exist(macAddr)) esp_now_add_peer(&peerInfo);  // Add the peer to the list

  sessionKey.clear();
  Serial.println("Onboarding of " + formatMacAddress(macAddr) + " complete\n");
  reset();
}

// Util for long messages
void sendLongMessage(const char* input_data, const uint8_t* macAddr) {
  int total_messages = (strlen(input_data) + MAX_DATA_SIZE - 1) / MAX_DATA_SIZE;
  int attempts = 1;
  char buffer[37];
  sprintf(buffer, "%u", esp_random());

  for (int i = 0; i < total_messages; i++) {
    message msg;
    strncpy(msg.id, buffer, sizeof(msg.id));
    msg.count = i;
    msg.total = total_messages;

    int length = strlen(input_data) - i * MAX_DATA_SIZE;
    if (length > MAX_DATA_SIZE) length = MAX_DATA_SIZE;
    strncpy(msg.data, &input_data[i * MAX_DATA_SIZE], length);
    if (length < MAX_DATA_SIZE) msg.data[length] = '\0';  // Ensure null termination

    esp_err_t result = esp_now_send(macAddr, (const uint8_t*)&msg, sizeof(msg));  // Send message

    if (result != ESP_OK) {
      if (attempts++ >= 3) {
        Serial.println("Could not send long message. Abbort...");
        reset();
        break;
      }
      --i;
    } else {
      attempts = 1;
    }
  }
}

// Util for long messages
String receiveLongMessage(const uint8_t* macAddr, const uint8_t* data, int len) {
  message* msg = (message*)data;  // Cast the data to a message

  // Find or create the message in the messages array
  MessageRec* fullMessage = NULL;
  for (auto& message : messages) {
    if (strcmp(message.id, msg->id) == 0) {
      fullMessage = &message;
      break;
    } else if (message.received == 0) {
      strcpy(message.id, msg->id);
      message.total = msg->total;
      fullMessage = &message;
      break;
    }
  }

  if (fullMessage == NULL) return "";  // If message couldn't be found or created, return an empty string

  // Store this part of the message
  strcpy(fullMessage->parts[msg->count].data, msg->data);
  fullMessage->parts[msg->count].index = msg->count;
  fullMessage->received++;

  // If received all parts of the message, combine them into a single string
  if (fullMessage->received == fullMessage->total) {
    String fullMessageStr = "";
    for (int i = 0; i < fullMessage->total; i++) fullMessageStr += fullMessage->parts[i].data;

    fullMessage->received = 0;  // Reset the message
    return fullMessageStr;      // Return the full message
  }

  return "";  // If not all parts of the message have been received, return an empty string
}

// Reset STATE
void reset() {
  esp_now_register_recv_cb(receiveSensorData);  // Register the recieve callback
  esp_now_unregister_send_cb();
  freeRSAKey();
  memset(clientMAC, 0, sizeof(clientMAC));
  STATE = DEFAULT;
  time_elapsed = 0;
  pixels.setPixelColor(0, pixels.Color(0, 17, 0));
  pixels.show();
}

// Helpers
// Check if request from device is allowed
bool deviceAllowed(const uint8_t* macAddr) {
  for (int i = 0; i < sizeof(allowedMacAddresses) / sizeof(allowedMacAddresses[0]); i++) {
    if (memcmp(macAddr, allowedMacAddresses[i], sizeof(allowedMacAddresses[i])) == 0) {
      return true;
    }
  }
  Serial.println("Transmission from unauthorized device (" + formatMacAddress(macAddr) + ") rejected.");
  return false;
}

// Formats MAC Address for prints
String formatMacAddress(const uint8_t* macAddr) {
  char res[18];
  snprintf(res, sizeof(res), "%02x:%02x:%02x:%02x:%02x:%02x", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
  return String(res);
}

void hexStringToByteArray(const String& hexString, uint8_t* byteArray, int byteArrayLength) {
  for (int i = 0; i < byteArrayLength; i++) {
    String hexByte = hexString.substring(i * 2, i * 2 + 2);
    byteArray[i] = (uint8_t)strtol(hexByte.c_str(), nullptr, 16);
  }
}

// ENCRYPTION
// Function to generate a 128-bit AES key and return it as a string
String generateAESKey() {
  mbedtls_entropy_context entropy;  // Context for entropy collection
  mbedtls_entropy_init(&entropy);   // Initialize entropy context to gather entropy used for random number generation

  mbedtls_ctr_drbg_context ctr_drbg;  // Context for the CTR_DRBG random number generator
  mbedtls_ctr_drbg_init(&ctr_drbg);   // Initialize the CTR_DRBG context

  uint32_t randomNumber = esp_random();
  char personalization[11];  // Personalization string for the DRBG seeding
  sprintf(personalization, "0x%08X", randomNumber);
  // Seed the CTR_DRBG context with entropy collected plus a personalization string for additional randomness
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)personalization, strlen(personalization));

  unsigned char key[16];  // Buffer to hold the 128-bit key (16 bytes)
  // Generate a random 128-bit key using the seeded CTR_DRBG context
  mbedtls_ctr_drbg_random(&ctr_drbg, key, sizeof(key));

  String keyHex = "";  // String to hold the hexadecimal representation of the key
  for (unsigned char i : key) {
    char hex[3];              // Temporary buffer to hold each byte in hex format
    sprintf(hex, "%02X", i);  // Format each byte of the key as two hexadecimal characters
    keyHex += hex;            // Append the hex string to the keyHex string
  }

  mbedtls_ctr_drbg_free(&ctr_drbg);  // Free the CTR_DRBG context to release any associated resources
  mbedtls_entropy_free(&entropy);    // Free the entropy context to release any associated resources

  return keyHex;  // Return the hexadecimal string representation of the key
}

// Function to initialize and generate RSA keys
void initializeRSAKey() {
  mbedtls_entropy_context entropy;  // Context for entropy collection
  mbedtls_entropy_init(&entropy);   // Initialize entropy context

  mbedtls_ctr_drbg_context ctr_drbg;  // Context for random number generator
  mbedtls_ctr_drbg_init(&ctr_drbg);   // Initialize CTR_DRBG context

  uint32_t randomNumber = esp_random();
  char personalization[11];  // Personalization string for the DRBG seeding
  sprintf(personalization, "0x%08X", randomNumber);
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)personalization, strlen(personalization));
  // Seed the DRBG

  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);  // Initialize RSA context
  int ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, RSA_KEY_LENGTH, RSA_EXPONENT);
  // Generate RSA key pair

  if (ret != 0) {
    Serial.print("Failed to generate RSA key with error code: ");
    Serial.println(ret);
  }
  if (mbedtls_rsa_check_privkey(&rsa) != 0) {
    Serial.println("Generated RSA private key is not valid.");
  }

  mbedtls_ctr_drbg_free(&ctr_drbg);  // Free the DRBG context
  mbedtls_entropy_free(&entropy);    // Free the entropy context
}

// Function to encrypt data using an external RSA public key
String encryptRSA(const String& data) {
  mbedtls_pk_context pk;  // Public key container
  mbedtls_pk_init(&pk);   // Initialize the public key container

  // Parse the public key from provided PEM string
  if (mbedtls_pk_parse_public_key(&pk, (const unsigned char*)pem_peer.c_str(), pem_peer.length() + 1) != 0) {
    mbedtls_pk_free(&pk);
    return "";  // Return empty if public key parsing fails
  }

  // Encrypt the data
  unsigned char output[1024];  // Buffer to hold encrypted data
  size_t olen;

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  uint32_t randomNumber = esp_random();
  char personalization[11];  // Personalization string for the DRBG seeding
  sprintf(personalization, "0x%08X", randomNumber);
  // Seed the CTR_DRBG context with entropy collected plus a personalization string for additional randomness
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)personalization, strlen(personalization));

  int ret = mbedtls_pk_encrypt(&pk, (const unsigned char*)data.c_str(), data.length(), output, &olen, sizeof(output), mbedtls_ctr_drbg_random, &ctr_drbg);

  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  if (ret != 0) return "";  // Return empty if encryption fails

  String encHex = "";
  for (size_t i = 0; i < olen; i++) {
    char hex[3];
    sprintf(hex, "%02X", output[i]);
    encHex += hex;
  }

  return encHex;  // Return the hex string of the encrypted data
}

// Function to decrypt data using RSA
String decryptRSA(const String& encHex) {
  if (mbedtls_rsa_check_privkey(&rsa) != 0) {
    Serial.println("RSA private key is not valid.");
  }

  unsigned char encData[1024];  // Buffer to store the encrypted data in binary form
  size_t encIndex = 0;          // Index for filling the encData buffer

  // Convert hexadecimal string back to binary data
  for (size_t i = 0; i < encHex.length(); i += 2) {
    sscanf(encHex.c_str() + i, "%02X", &encData[encIndex++]);  // Parse two hexadecimal characters at a time_elapsed
  }

  unsigned char output[1024];  // Buffer to hold the decrypted data
  size_t olen;                 // Variable to store the length of the decrypted data

  mbedtls_ctr_drbg_context ctr_drbg;  // Context for the CTR_DRBG random number generator
  mbedtls_entropy_context entropy;    // Context for entropy collection
  mbedtls_entropy_init(&entropy);     // Initialize the entropy context
  mbedtls_ctr_drbg_init(&ctr_drbg);   // Initialize the CTR_DRBG context

  uint32_t randomNumber = esp_random();
  char personalization[11];  // Personalization string for the DRBG seeding
  sprintf(personalization, "0x%08X", randomNumber);
  // Seed the CTR_DRBG context with entropy collected plus a personalization string for additional randomness
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)personalization, strlen(personalization));

  // Decrypt the data using the private key
  int ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &olen, encData, output, sizeof(output));

  mbedtls_ctr_drbg_free(&ctr_drbg);  // Free the CTR_DRBG context
  mbedtls_entropy_free(&entropy);    // Free the entropy context

  if (ret != 0) {
    Serial.print("Decryption failed with error: ");
    Serial.println(ret);
    return "";
  }

  if (mbedtls_rsa_check_privkey(&rsa) != 0) {
    Serial.println("RSA private key is not valid.");
  }

  return String((char*)output);  // Convert the decrypted binary data back to a string and return it
}

String exportPublicKey() {
  char buf[626];  // Ensure buffer is large enough for the key
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);  // Initialize the PK context

  // Setup the PK context to hold an RSA key
  if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
    mbedtls_pk_free(&pk);
    return "";
  }

  // Copy the RSA context to the PK context
  mbedtls_rsa_context* rsa_copy = mbedtls_pk_rsa(pk);
  mbedtls_rsa_copy(rsa_copy, &rsa);  // Correctly copy RSA context

  // Check if the public key can be written into buffer
  if (mbedtls_pk_write_pubkey_pem(&pk, (unsigned char*)buf, sizeof(buf)) < 0) {
    mbedtls_pk_free(&pk);
    return "";  // Return empty string on failure
  }

  mbedtls_pk_free(&pk);  // Free the PK context
  return String(buf);    // Return the public key in PEM format
}

// Function to clean up RSA context when no longer needed
void freeRSAKey() {
  volatile char* p = const_cast<char*>(pem_peer.c_str());  // Access the underlying character array of the string
  size_t len = pem_peer.length();                          // Get the length of the string
  while (len--) *p++ = 0;                                  // Overwrite each character with zero
  pem_peer.clear();                                        // Clear the string to remove all content and reduce its size to zero

  secureZeroMemory(&rsa, sizeof(rsa));
  mbedtls_rsa_free(&rsa);  // Free the RSA context and all associated resources
}

void secureZeroMemory(void* ptr, size_t size) {
  volatile uint8_t* p = (volatile uint8_t*)ptr;
  while (size--) *p++ = 0;
}
