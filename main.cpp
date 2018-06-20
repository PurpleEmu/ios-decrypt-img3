#include "common.h"
#include <openssl/aes.h>

void hextou8array(char* hex, u8* buffer, u32 bytes)
{
    bytes = strlen(hex) / 2;
    for(int i = 0; i < bytes; i++)
    {
        u8 byte;
        sscanf(hex, "%2hhx", &byte);
        buffer[i] = byte;
        hex += 2;
    }
}

void decrypt(uint8_t* ciphertext, uint32_t length, uint8_t* key,
             uint8_t* iv, uint8_t* plaintext)
{
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);
    memset(plaintext, 0, length);
    AES_cbc_encrypt(ciphertext, plaintext, length, &aes_key, iv, AES_DECRYPT);
}

int main(int ac, char** av)
{
    if(ac < 4) return 1;

    FILE* infp = fopen(av[1], "rb");
    if(!infp) return 2;

    u8* indata = (u8*)malloc(0x04000000);
    u8* outdata = (u8*)malloc(0x04000000);

    u32 filesize = 0;
    fseek(infp, 0, SEEK_END);
    filesize = ftell(infp);
    fseek(infp, 0, SEEK_SET);

    char magicimg3[4];
    magicimg3[0] = fgetc(infp);
    magicimg3[1] = fgetc(infp);
    magicimg3[2] = fgetc(infp);
    magicimg3[3] = fgetc(infp);

    if(magicimg3[0] == '3' && magicimg3[1] == 'g' && magicimg3[2] == 'm' && magicimg3[3] == 'I')
    {
        fseek(infp, 0x10, SEEK_CUR);
        filesize -= 0x14;
        char magicimg3tag[4];
        magicimg3tag[0] = fgetc(infp);
        magicimg3tag[1] = fgetc(infp);
        magicimg3tag[2] = fgetc(infp);
        magicimg3tag[3] = fgetc(infp);
        if(magicimg3tag[0] == 'A' && magicimg3tag[1] == 'T' && magicimg3tag[2] == 'A' && magicimg3tag[3] == 'D')
        {
            uint32_t totallength;
            fread(&totallength, 1, 4, infp);
            fseek(infp, 4, SEEK_CUR);
            filesize = totallength - 0xc;

            if(fread(indata, 1, filesize, infp) != filesize)
            {
                free(indata);
                free(outdata);
                fclose(infp);
                return 4;
            }
        }

        u8 key[16];
        u8 iv[16];

        hextou8array(av[3], key, 16);
        if(ac > 4) hextou8array(av[4], iv, 16);
        else memset(iv, 0, 16);

        decrypt(indata, filesize, key, iv, outdata);

        FILE* outfp = fopen(av[2], "wb");
        fwrite(outdata, 1, filesize, outfp);
        fclose(outfp);
        fclose(infp);
        free(indata);
        free(outdata);
    }
    else
    {
        fseek(infp, 0, SEEK_SET);
        char magic8900[4];
        magic8900[0] = fgetc(infp);
        magic8900[1] = fgetc(infp);
        magic8900[2] = fgetc(infp);
        magic8900[3] = fgetc(infp);
        u32 addr = 0x4;

        if(magic8900[0] == '8' && magic8900[1] == '9' && magic8900[2] == '0' && magic8900[3] == '0')
        {
            fseek(infp, 3, SEEK_CUR);
            addr += 0x3;
            u8 format = fgetc(infp);
            addr += 0x1;
            fseek(infp, 4, SEEK_CUR);
            addr += 0x4;

            u32 datalength;
            fread(&datalength, 1, 4, infp);

            filesize = datalength;
            fseek(infp, 0x800, SEEK_SET);
            fread(indata, 1, filesize, infp);
            if((format & 7) == 3)
            {
                u8 key_837[16];
                u8 empty_iv[16];
                memset(empty_iv, 0, 16);
                hextou8array(av[3], key_837, 16);
                decrypt(indata, filesize, key_837, empty_iv, outdata);
            }

            filesize -= 0x400;

            FILE* outfp = fopen(av[2], "wb");
            fwrite(outdata + 0x400, 1, filesize, outfp);
            fclose(outfp);
        }
        free(indata);
        free(outdata);
        fclose(infp);
        return 0;
    }
}