#include <stdio.h>
#include <string.h>
#include <microhttpd.h>
#include "fingerprint_capture.h"
#include "fingerprint_selection.h"
#include <dpfpdd.h>
#include <stdlib.h>
#include <signal.h>
#include <locale.h>
#include <pthread.h>

#define PORT 5050
#define CONNECTION_LIMIT 10  // Ajusta según tus necesidades

struct ThreadData {
    struct MHD_Connection *connection;
    const char *url;
    const char *method;
};

void sigint_handler(int signum) {
    // No hacer nada, simplemente ignorar la señal
}
// funcion para leer el index actual
int read_current_index();
// funcion para incrementar el index actual
void increment_current_index(int index);
// Función para decodificar en Base64
char* base64_decode(const unsigned char* input, size_t length, size_t* output_length);
// Función para codificar en Base64
char* base64_encode(const unsigned char* input, size_t length, size_t* output_length);
// send response
int send_response(char *buffer, struct MHD_Connection *connection, struct MHD_Response *response);
// Función para leer el contenido de un archivo en un búfer
unsigned char *read_file_fingerprint(const char* filename);
// Función para leer el contenido de un archivo en un búfer
unsigned char* read_file(const char* filename, size_t* length);
// Función para manejar las solicitudes HTTP al enpoint /validate
int validate_endpoint(const char *name, struct MHD_Connection *connection, struct MHD_Response *response);

int request_handler2(void *cls, struct MHD_Connection *connection,
                     const char *url, const char *method,
                     const char *version, const char *upload_data,
                     size_t *upload_data_size, void **con_cls) {

    if (strcmp(url, "/close") == 0) {
        FILE* fp = popen("tmux send-keys -t finger_sesion C-c", "r");

        if (fp == NULL) {
            perror("popen");
            exit(EXIT_FAILURE);
        }

        char buffer[256];
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            printf("%s", buffer);
        }

        pclose(fp);
        
        const char *json_response = "{\"message\": \"huellero cancelado\", \"type\": \"true\"}";

        struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_response),
                                                                        (void *) json_response,
                                                                        MHD_RESPMEM_MUST_COPY);
         
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);

        return ret;
    }

    return MHD_NO;  // Página no encontrada
}
// Función para manejar las solicitudes HTTP
int request_handler(void *cls, struct MHD_Connection *connection,
                    const char *url, const char *method,
                    const char *version, const char *upload_data,
                    size_t *upload_data_size, void **con_cls) {

    struct MHD_Response *response;

    if (strcmp(url, "/isconnected") == 0) { 
        // Inicialización del lector de huellas y variables
      //  int result = dpfpdd_init();
        DPFPDD_DEV hReader = NULL;
        int dpi = 0;
        int bStop = 0;
        int result = dpfpdd_init();
        char szReader[MAX_DEVICE_NAME_LENGTH];
        sigset_t sigmask;

        // Configuración de máscara de señales
        sigfillset(&sigmask);
        pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
        
        // Configuración de localización
        setlocale(LC_ALL, "");
        strncpy(szReader, "", sizeof(szReader));

        // Intento de obtener información sobre el lector de huellas
        unsigned int nReaderCnt = 1;
        while(!bStop) {
            // Consulta de información de los dispositivos
    
            DPFPDD_DEV_INFO* pReaderInfo = (DPFPDD_DEV_INFO*)malloc(sizeof(DPFPDD_DEV_INFO) * nReaderCnt);
            while(NULL != pReaderInfo) {
                unsigned int i = 0;
                for(i = 0; i < nReaderCnt; i++) {
                    pReaderInfo[i].size = sizeof(DPFPDD_DEV_INFO);
                }

                unsigned int nNewReaderCnt = nReaderCnt;
                int result2 = dpfpdd_query_devices(&nNewReaderCnt, pReaderInfo);

                // Manejo de errores en la consulta de dispositivos
                if(DPFPDD_SUCCESS != result2 && DPFPDD_E_MORE_DATA != result2) {

                    response = MHD_create_response_from_buffer(strlen("{\"message\": \"Huellero no conectado\", \"type\": \"false\"} "),
                                                            (void *) "{\"message\": \"Huellero no conectado\", \"type\": \"false\"} ",
                                                            MHD_RESPMEM_MUST_COPY);
                                MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
                                MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                                MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");

                                    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
                                    MHD_destroy_response(response);
                                    return ret;
                    printf("Error en dpfpdd_query_devices(): %d", result2);
                    free(pReaderInfo);
                    pReaderInfo = NULL;
                    nReaderCnt = 0;
                    break;
                }

                if(DPFPDD_E_MORE_DATA == result2) {
                    DPFPDD_DEV_INFO* pri = (DPFPDD_DEV_INFO*)realloc(pReaderInfo, sizeof(DPFPDD_DEV_INFO) * nNewReaderCnt);
                    if(NULL == pri) {
                        printf("Error en realloc(): ENOMEM");
                        response = MHD_create_response_from_buffer(strlen("{\"message\": \"Huellero no conectado\", \"type\": \"false\"} "),
                                                            (void *) "{\"message\": \"Huellero no conectado\", \"type\": \"false\"} ",
                                                            MHD_RESPMEM_MUST_COPY);
                                    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
                                    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                                    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");

                                    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
                                    MHD_destroy_response(response);
                                    return ret;
                    }
                    pReaderInfo = pri;
                    nReaderCnt = nNewReaderCnt;
                    continue;
                }

                nReaderCnt = nNewReaderCnt;
                break;
            }

            // Selección del lector y obtención de sus capacidades
            int result2 = 0;
            int nChoice = 0;
    

            // Si no se encuentra ningún lector de huellas
            if(0 == nReaderCnt) {
                response = MHD_create_response_from_buffer(strlen("{\"message\": \"Huellero no conectado\", \"type\": \"false\"} "),
                                                            (void *) "{\"message\": \"Huellero no conectado\", \"type\": \"false\"} ",
                                                            MHD_RESPMEM_MUST_COPY);
                                MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
                                MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                                MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
                
                if(NULL != hReader){
                    result = dpfpdd_close(hReader);
                    hReader = NULL;
                } 
                
                int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
                MHD_destroy_response(response);
                return ret;
                dpfpdd_exit();  

            } else {
                // Selección y apertura del lector de huellas
                hReader = SelectAndOpenReader(szReader, sizeof(szReader),&dpi);
                                response = MHD_create_response_from_buffer(strlen("{\"message\": \"Huellero  conectado\", \"type\": \"true\"} "),
                                                            (void *) "{\"message\": \"Huellero  conectado\", \"type\": \"true\"} ",
                                                            MHD_RESPMEM_MUST_COPY);
                                MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
                                MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                                MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
                
                if(NULL != hReader){
                    result = dpfpdd_close(hReader);
                    hReader = NULL;
                } 
                
                int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
                MHD_destroy_response(response);
                return ret;
                dpfpdd_exit();  

            } 
            
            if(NULL != pReaderInfo) free(pReaderInfo);
            pReaderInfo = NULL;
            nReaderCnt = 0;
        }
        
    }

    if (strcmp(url, "/capture") == 0) {
        unsigned char* pFeatures1 = NULL;
	    unsigned int nFeatures1Size = 0;
        DPFPDD_DEV hReader = NULL;
        int dpi = 0;
        int bStop = 0;
        int result = dpfpdd_init();
        char szReader[MAX_DEVICE_NAME_LENGTH];
        sigset_t sigmask;
        // Configuración de máscara de señales
        sigfillset(&sigmask);
        pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
        // Configuración de localización
        setlocale(LC_ALL, "");
        strncpy(szReader, "", sizeof(szReader));

        hReader = SelectAndOpenReader(szReader, sizeof(szReader),&dpi);

        CaptureFinger2("any finger", hReader, dpi,DPFJ_FMD_ISO_19794_2_2005, &pFeatures1, &nFeatures1Size);

        // create bin file for save fingerprint (pFeatures1 and nFeatures1Size)
        int index = read_current_index();

        char input_file_name[512];
        sprintf(input_file_name, "fingers/fingerprint_%d.bin", index);

        FILE *f = fopen(input_file_name, "wb");
        if (f == NULL)
        {
            printf("Error opening file!\n");
            exit(1);
        }

        fwrite(pFeatures1, sizeof(char), nFeatures1Size, f);
        fclose(f);
        increment_current_index(index+1);
        //content
        size_t input_length;
        unsigned char* input_content = read_file(input_file_name, &input_length);
        size_t encoded_length;
        char* encoded_content = base64_encode(input_content, input_length, &encoded_length);

        char buffer[512];
        sprintf(buffer, "{\"message\": \"success\", \"content\":\"%s\", \"index\":\"%d\" }", encoded_content, index);
        response = MHD_create_response_from_buffer(strlen(buffer),
                                        (void *) buffer,
                                        MHD_RESPMEM_MUST_COPY);
        dpfpdd_exit();
        MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    if (strcmp(url, "/compare") == 0) {
        // read params of querystring for fingerprint
        const char *index_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "index");
        int index = atoi(index_str);
        char* name[255];
        sprintf(name, "fingers/fingerprint_%d.bin", index);
        FILE *f = fopen(name, "w");
        if (f == NULL)
        {
            printf("Error opening file!\n");
            exit(1);
        }

        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);  //same as rewind(f);

        unsigned char *pFeatures2 = malloc(fsize + 1);
        fread(pFeatures2, fsize, 1, f);
        fclose(f);

        unsigned char* pFeatures1 = NULL;
        unsigned int nFeatures1Size = 0;
        unsigned int nFeatures2Size = 0;
        DPFPDD_DEV hReader = NULL;
        int dpi = 0;
        int bStop = 0;
        int result = dpfpdd_init();
        char szReader[MAX_DEVICE_NAME_LENGTH];
        sigset_t sigmask;
        // Configuración de máscara de señales
        sigfillset(&sigmask);
        pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
        // Configuración de localización
        setlocale(LC_ALL, "");
        strncpy(szReader, "", sizeof(szReader));

        hReader = SelectAndOpenReader(szReader, sizeof(szReader),&dpi);

        CaptureFinger2("any finger", hReader, dpi,DPFJ_FMD_ISO_19794_2_2005, &pFeatures1, &nFeatures1Size);

        unsigned int falsematch_rate = 0;
        const unsigned int target_falsematch_rate = DPFJ_PROBABILITY_ONE / 100000; //target rate is 0.00001
        long mseconds;
        struct timeval tv1, tv2;
        gettimeofday(&tv1, NULL);
        int new_result = dpfj_compare(DPFJ_FMD_ISO_19794_2_2005, pFeatures1, nFeatures1Size, 0,
            DPFJ_FMD_ISO_19794_2_2005, pFeatures2, nFeatures2Size, 0,
            &falsematch_rate);

        gettimeofday(&tv2, NULL);
        mseconds = (tv2.tv_sec - tv1.tv_sec) * 1000 + (tv2.tv_usec - tv1.tv_usec) / 1000; //time of operation in milliseconds
        // show features in console
        char buffer[512];
        if(DPFJ_SUCCESS == result){
            if(falsematch_rate < target_falsematch_rate){
                printf("Fingerprints match.\n\n\n");
                sprintf(buffer, "{\"message\": \"%s\", \"type\": \"true\" }", "match");
            }
            else{
                printf("Fingerprints did not match.\n\n\n");
                sprintf(buffer, "{\"message\": \"%s\", \"type\": \"true\"}", "not match");
            }
        }else{
            sprintf(buffer, "{\"message\": \"%d\", \"type\": \"false\"}", "not connected");
        }

        response = MHD_create_response_from_buffer(strlen(buffer),
                                        (void *) buffer,
                                        MHD_RESPMEM_MUST_COPY);
        dpfpdd_exit();
        MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;

    }

    if (strcmp(url, "/validate") == 0) {
        const char *index_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "index");
        int index = atoi(index_str);
        char name[255];
        sprintf(name, "fingers/fingerprint_%d.bin", index);
        return validate_endpoint(name, connection, response);
    }

    if (strcmp(url, "/connect") == 0) {
        // Inicialización del lector de huellas y variables
        //  int result = dpfpdd_init();
        DPFPDD_DEV hReader = NULL;
        int dpi = 0;
        int bStop = 0;
        int result = dpfpdd_init();
        char szReader[MAX_DEVICE_NAME_LENGTH];
        sigset_t sigmask;

        // Configuración de máscara de señales
        sigfillset(&sigmask);
        pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
        // Configuración de localización
        setlocale(LC_ALL, "");
        strncpy(szReader, "", sizeof(szReader));

        // Intento de obtener información sobre el lector de huellas
        unsigned int nReaderCnt = 1;
        while(!bStop) {
            // Consulta de información de los dispositivos
    
            DPFPDD_DEV_INFO* pReaderInfo = (DPFPDD_DEV_INFO*)malloc(sizeof(DPFPDD_DEV_INFO) * nReaderCnt);
            while(NULL != pReaderInfo) {
                unsigned int i = 0;
                for(i = 0; i < nReaderCnt; i++) {
                    pReaderInfo[i].size = sizeof(DPFPDD_DEV_INFO);
                }

                unsigned int nNewReaderCnt = nReaderCnt;
                int result2 = dpfpdd_query_devices(&nNewReaderCnt, pReaderInfo);

                // Manejo de errores en la consulta de dispositivos
                if(DPFPDD_SUCCESS != result2 && DPFPDD_E_MORE_DATA != result2) {

                    response = MHD_create_response_from_buffer(strlen("{\"message\": \"Huellero no conectado\", \"type\": \"false\"} "),
                                                            (void *) "{\"message\": \"Huellero no conectado\", \"type\": \"false\"} ",
                                                            MHD_RESPMEM_MUST_COPY);
                                MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
                                MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                                MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");

                                    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
                                    MHD_destroy_response(response);
                                    return ret;
                    printf("Error en dpfpdd_query_devices(): %d", result2);
                    free(pReaderInfo);
                    pReaderInfo = NULL;
                    nReaderCnt = 0;
                    break;
                }

                if(DPFPDD_E_MORE_DATA == result2) {
                    DPFPDD_DEV_INFO* pri = (DPFPDD_DEV_INFO*)realloc(pReaderInfo, sizeof(DPFPDD_DEV_INFO) * nNewReaderCnt);
                    if(NULL == pri) {
                        printf("Error en realloc(): ENOMEM");
                        break;
                        response = MHD_create_response_from_buffer(strlen("{\"message\": \"Huellero no conectado\", \"type\": \"false\"} "),
                                                            (void *) "{\"message\": \"Huellero no conectado\", \"type\": \"false\"} ",
                                                            MHD_RESPMEM_MUST_COPY);
                                    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
                                    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                                    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");

                                    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
                                    MHD_destroy_response(response);
                                    return ret;
                    }
                    pReaderInfo = pri;
                    nReaderCnt = nNewReaderCnt;
                    continue;
                }

                nReaderCnt = nNewReaderCnt;
                break;
            }

            // Selección del lector y obtención de sus capacidades
            int result2 = 0;
            int nChoice = 0;
    

            // Si no se encuentra ningún lector de huellas
            if(0 == nReaderCnt) {
                response = MHD_create_response_from_buffer(strlen("{\"message\": \"Huellero no conectado\", \"type\": \"false\"} "),
                                                            (void *) "{\"message\": \"Huellero no conectado\", \"type\": \"false\"} ",
                                                            MHD_RESPMEM_MUST_COPY);
                                MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
                                MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                                MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
                
                if(NULL != hReader){
                    result = dpfpdd_close(hReader);
                    hReader = NULL;
                } 
                
                int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
                MHD_destroy_response(response);
                return ret;
                dpfpdd_exit();  

            } else {
                // Selección y apertura del lector de huellas
                hReader = SelectAndOpenReader(szReader, sizeof(szReader),&dpi);

                unsigned char* pFeatures1 = NULL;
                unsigned int nFeatures1Size = 0;
                unsigned char* pFeatures2 = NULL;
                unsigned int nFeatures2Size = 0;

                int bStop = 0;
                char* base64Data = CaptureFinger("any finger", hReader, dpi,DPFJ_FMD_ISO_19794_2_2005, &pFeatures1);
                char* estado = "false";

                char* readerName = (char*)malloc( sizeof(szReader));
                if (readerName != NULL) {
                    strncpy(readerName, szReader,  sizeof(szReader));
                }

                unsigned int nReaderCnt = 1;
                DPFPDD_DEV_INFO* pReaderInfo = (DPFPDD_DEV_INFO*)malloc(sizeof(DPFPDD_DEV_INFO) * nReaderCnt);
                while(NULL != pReaderInfo) {
                    unsigned int i = 0;
                    for(i = 0; i < nReaderCnt; i++) {
                        pReaderInfo[i].size = sizeof(DPFPDD_DEV_INFO);
                    }

                    unsigned int nNewReaderCnt = nReaderCnt;
                    int result = dpfpdd_query_devices(&nNewReaderCnt, pReaderInfo);

                    // Manejo de errores en la consulta de dispositivos
                    if(DPFPDD_SUCCESS != result && DPFPDD_E_MORE_DATA != result) {
                        printf("Error en dpfpdd_query_devices(): %d", result);
                        free(pReaderInfo);
                        pReaderInfo = NULL;
                        nReaderCnt = 0;
                        break;
                    }

                    if(DPFPDD_E_MORE_DATA == result) {
                        DPFPDD_DEV_INFO* pri = (DPFPDD_DEV_INFO*)realloc(pReaderInfo, sizeof(DPFPDD_DEV_INFO) * nNewReaderCnt);
                        if(NULL == pri) {
                            printf("Error en realloc(): ENOMEM");
                            break;
                        }
                        pReaderInfo = pri;
                        nReaderCnt = nNewReaderCnt;
                        continue;
                    }

                    nReaderCnt = nNewReaderCnt;
                    break;
                }

                int result = 0;
                int nChoice = 0;

                char* divice_name =  pReaderInfo[nChoice].descr.serial_num; 

                if(strlen(base64Data) > 30  ){
                    estado = "true";  

                    const char* input_file_name = "fingerprint.bmp";
                            
                    size_t input_length;
                    unsigned char* input_content = read_file(input_file_name, &input_length);

                    size_t encoded_length;
                    char* encoded_content = base64_encode(input_content, input_length, &encoded_length);

                    size_t legth = strlen(encoded_content);
                    char buffer[legth+50];

                    sprintf(buffer, "{\"message\": \"%s\", \"type\": \"%s\", \"serial_num_divice\": \"%s\"}", encoded_content , estado, divice_name);
                    response = MHD_create_response_from_buffer(strlen(buffer),
                                                    (void *)buffer,
                                                    MHD_RESPMEM_MUST_COPY);
                } else {
                    char buffer[512];
                    sprintf(buffer, "{\"message\": \"%s\", \"type\": \"%s\", \"serial_num_divice\": \"%s\"}", base64Data , estado, divice_name);
                    response = MHD_create_response_from_buffer(strlen(buffer),
                                                    (void *)buffer,
                                                    MHD_RESPMEM_MUST_COPY);
                }
                
                if(NULL != hReader){
                    result = dpfpdd_close(hReader);
                    hReader = NULL;
                } 

                dpfpdd_exit();  
                                MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
                                MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                                MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");

                int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
                MHD_destroy_response(response);
                
                return ret;
            } 

            if(NULL != pReaderInfo) free(pReaderInfo);
            pReaderInfo = NULL;
            nReaderCnt = 0;
        }
        
    }

    return MHD_NO;  // Página no encontrada
}

// Función principal
int main() {

    signal(SIGINT, sigint_handler);


   // while (keep_running) {
        struct MHD_Daemon *daemon;
        struct MHD_Daemon *daemon2;

       daemon2 = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG, 5051, NULL, NULL,
                                &request_handler2, NULL,
                                MHD_OPTION_CONNECTION_LIMIT, 10,
                                MHD_OPTION_END);
        // Inicia el demonio de MHD
        daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG, PORT, NULL, NULL,
                                &request_handler, NULL,
                                MHD_OPTION_CONNECTION_LIMIT, 10,
                                MHD_OPTION_END);

 
   // }
    if (daemon == NULL) {
        printf("Error al iniciar el servidor\n");
        return 1;
    }

    printf("Servidor escuchando en http://127.0.0.1:%d/\n", PORT);
    printf("Presiona Enter para detener el servidor...\n");
    getchar();

    // Detiene el demonio
    MHD_stop_daemon(daemon);
    MHD_stop_daemon(daemon2);

    return 0;
   
}

// Función para codificar Base64 a  binarios
char* base64_decode(const unsigned char* input, size_t length, size_t* output_length) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    *output_length = length / 4 * 3;
    if (input[length - 1] == '=') {
        (*output_length)--;
    }
    if (input[length - 2] == '=') {
        (*output_length)--;
    }

    char* decoded_data = (char*)malloc(*output_length);
    if (decoded_data == NULL) {
        fprintf(stderr, "Error de asignación de memoria\n");
        exit(EXIT_FAILURE);
    }

    size_t i, j;
    for (i = 0, j = 0; i < length; i += 4, j += 3) {
        uint32_t sextet_a = input[i] == '=' ? 0 & i++ : strchr(base64_chars, input[i]) - base64_chars;
        uint32_t sextet_b = input[i] == '=' ? 0 & i++ : strchr(base64_chars, input[i]) - base64_chars;
        uint32_t sextet_c = input[i] == '=' ? 0 & i++ : strchr(base64_chars, input[i]) - base64_chars;
        uint32_t sextet_d = input[i] == '=' ? 0 & i++ : strchr(base64_chars, input[i]) - base64_chars;

        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < *output_length) {
            decoded_data[j] = (triple >> 16) & 0xFF;
        }
        if (j + 1 < *output_length) {
            decoded_data[j + 1] = (triple >> 8) & 0xFF;
        }
        if (j + 2 < *output_length) {
            decoded_data[j + 2] = triple & 0xFF;
        }
    }

    return decoded_data;
}



// Función para codificar datos binarios a Base64
char* base64_encode(const unsigned char* input, size_t length, size_t* output_length) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    *output_length = 4 * ((length + 2) / 3);

    char* encoded_data = (char*)malloc(*output_length + 1);
    if (encoded_data == NULL) {
        fprintf(stderr, "Error de asignación de memoria\n");
        exit(EXIT_FAILURE);
    }

    size_t i, j;
    for (i = 0, j = 0; i < length; i += 3, j += 4) {
        uint32_t octet_a = i < length ? input[i] : 0;
        uint32_t octet_b = i + 1 < length ? input[i + 1] : 0;
        uint32_t octet_c = i + 2 < length ? input[i + 2] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded_data[j] = base64_chars[(triple >> 18) & 0x3F];
        encoded_data[j + 1] = base64_chars[(triple >> 12) & 0x3F];
        encoded_data[j + 2] = i + 1 < length ? base64_chars[(triple >> 6) & 0x3F] : '=';
        encoded_data[j + 3] = i + 2 < length ? base64_chars[triple & 0x3F] : '=';
    }

    encoded_data[*output_length] = '\0';
    return encoded_data;
}

// Función para leer el contenido de un archivo en un búfer
unsigned char* read_file(const char* filename, size_t* length) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Error al abrir el archivo");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* content = (unsigned char*)malloc(*length);
    fread(content, 1, *length, file);
    fclose(file);

    return content;
}

int read_current_index(){
    FILE *f = fopen("index.txt", "r");
    if (f == NULL)
    {
        printf("Error opening file!\n");
        exit(1);
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  //same as rewind(f);

    char *string = malloc(fsize + 1);
    fread(string, fsize, 1, f);
    fclose(f);

    int index = atoi(string);
    return index;
}

void increment_current_index(int index){
    FILE *f = fopen("index.txt", "w");
    if (f == NULL)
    {
        printf("Error opening file!\n");
        exit(1);
    }
    fprintf(f, "%d", index);
    fclose(f);
}

int send_response(char *buffer, struct MHD_Connection *connection, struct MHD_Response *response) {
    response = MHD_create_response_from_buffer(strlen(buffer),
                                    (void *) buffer,
                                    MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

unsigned char *read_file_fingerprint(const char* filename){
    FILE *f = fopen(filename, "rb");
    if (f == NULL)
    {
        printf("Error opening file!\n");
        exit(1);
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  //same as rewind(f);

    unsigned char *pFeatures2 = malloc(fsize + 1);
    fread(pFeatures2, fsize, 1, f);
    fclose(f);
    return pFeatures2;
}


int validate_endpoint(const char *name, struct MHD_Connection *connection, struct MHD_Response *response) {
    printf("%s.\n\n\n",name);
    size_t nFeatures1Size = 0;
    size_t nFeatures2Size = 0;
    unsigned char* pFeatures1;
    unsigned char* pFeatures2 = read_file(name, &nFeatures2Size);
    
    DPFPDD_DEV hReader = NULL;
    int dpi = 0;
    int bStop = 0;
    int result = dpfpdd_init();
    char szReader[MAX_DEVICE_NAME_LENGTH];
    sigset_t sigmask;
    // Configuración de máscara de señales
    sigfillset(&sigmask);
    pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    // Configuración de localización
    setlocale(LC_ALL, "");
    strncpy(szReader, "", sizeof(szReader));

    hReader = SelectAndOpenReader(szReader, sizeof(szReader),&dpi);

    CaptureFinger2("any finger", hReader, dpi,DPFJ_FMD_ISO_19794_2_2005, &pFeatures1, &nFeatures1Size);

    unsigned int falsematch_rate = 0;
    const unsigned int target_falsematch_rate = DPFJ_PROBABILITY_ONE / 100000; //target rate is 0.00001
    long mseconds;
    struct timeval tv1, tv2;
    gettimeofday(&tv1, NULL);
    int new_result = dpfj_compare(DPFJ_FMD_ISO_19794_2_2005, pFeatures1, nFeatures1Size, 0,
        DPFJ_FMD_ISO_19794_2_2005, pFeatures2, nFeatures2Size, 0,
        &falsematch_rate);

    gettimeofday(&tv2, NULL);
    mseconds = (tv2.tv_sec - tv1.tv_sec) * 1000 + (tv2.tv_usec - tv1.tv_usec) / 1000; //time of operation in milliseconds
    // show features in console
    char buffer[512];
    if(DPFJ_SUCCESS == result){
        if(falsematch_rate < target_falsematch_rate){
            printf("Fingerprints match.\n\n\n");
            sprintf(buffer, "{\"message\": \"%s\", \"type\": \"true\" }", "match");
        }
        else{
            printf("Fingerprints did not match.\n\n\n");
            sprintf(buffer, "{\"message\": \"%s\", \"type\": \"true\"}", "not match");
        }
    }else{
        sprintf(buffer, "{\"message\": \"%d\", \"type\": \"false\"}", "not connected");
    }
    dpfpdd_exit();
    return send_response(buffer, connection, response);
}