#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <ctype.h>

#define WHITESPACE " \t\n"
#define MAX_COMMAND_LENGTH 255
#define MAX_ARGUMENTS 5

//struct that represents FAT32 variables used in this program
struct FAT32_BPB 
{
    char BS_OEMName[8];
    uint16_t BPB_BytsPerSec;
    uint8_t BPB_SecPerClus;
    uint16_t BPB_RsvdSecCnt;
    uint8_t BPB_NumFATs;
    uint16_t BPB_RootEntCnt;  // For FAT32, this is 0
    char BS_VolLab[11];
    uint32_t BPB_FATSz32;
    uint32_t BPB_RootClus;

    int32_t RootDirSectors;   // Calculated, not part of the actual BPB
    int32_t FirstDataSector;  // Calculated, not part of the actual BPB
    int32_t FirstSectorOfCluster;  // Calculated, not part of the actual BPB
};

int32_t currentDir;
char formattedDir[12]; // string to ocntain fully changed or formatted string
FILE *fp= NULL;
int currentAddr =-1;
int flag =0;


struct __attribute__((__packed__)) DirectoryEntry
{
    char DIR_Name[11];
    uint8_t DIR_Attr;
    uint8_t Unused1[8];
    uint16_t DIR_FirstClusterHigh;
    uint8_t Unused2[4];
    uint16_t DIR_FirstClusterLow;
    uint32_t DIR_FileSize;
};

struct DirectoryEntry dirEnt[16]; 

int LBAToOffset(int32_t sector) // fn to find the starting address of a block of data given the sector number
{
  return ( ( sector - 2 ) * BPB_BytsPerSec ) + ( BPB_BytsPerSec * BPB_RsvdSecCnt ) + 
            ( BPB_NumFATs * BPB_FATSz32 * BPB_BytsPerSec ); //returns the value of the address for that block of data
}

int16_t NextLB(uint32_t sector) // fn that  look up into the first FAT and return the logical block address of the block in the file.
{
    uint32_t FATAdd = (BPB_BytesPerSec * BPB_RsvdSecCnt) + (sector * 4);
    int16_t value;
    fseek(fp, FATAdd, SEEK_SET);
    fread(&value, 2, 1, fp);
    return value;
}

void set_values()
{
  fseek(fp, 11, SEEK_SET);
  fread(&BPB_BytsPerSec, 1, 2, fp);
 
  fseek(fp, 13, SEEK_SET);
  fread(&BPB_SecPerClus, 1, 1, fp);

  fseek(fp, 14, SEEK_SET);
  fread(&BPB_RsvdSecCnt, 2, 1, fp);
 
  fseek(fp, 16, SEEK_SET);
  fread(&BPB_NumFATs, 1, 1, fp);

  fseek(fp, 36, SEEK_SET);
  fread(&BPB_FATSz32, 2, 2, fp);
}

int main() 
{
    char *cmdLine = (char *)malloc(MAX_COMMAND_SIZE );
    if (!cmd_str) 
    {
        perror("Memory allocation failed");
        return EXIT_FAILURE;
    }
    
    while (1) 
    {
        printf("mfs> ");
        while (!fgets(cmdLine, MAX_COMMAND_SIZE, stdin));

        char *token[MAX_NUM_ARGUMENTS]; // parse input
        char argPtr; // ptr to token 
        char *currentString;  = strdup(cmdLine);
        
        char *currentRoot = currentString; // move the currentString pointer to keep track of its original value
        
        // Tokenize the input stringswith whitespace used as the delimiter
        while ( ( (argPtr = strsep(&currentString, WHITESPACE ) ) != NULL) && (tokenCount<MAX_NUM_ARGUMENTS))
        {
            token[tokenCount] = strndup( argPtr, MAX_COMMAND_SIZE );
            if( strlen( token[tokenCount] ) == 0 )
            {
                token[tokenCount] = NULL;
            }
        tokenCount++;
    }
    }
    free(cmdLine);
    return 0;
}

void openImg()
{
    if (fp != NULL)
    {
      printf("Error: File system image already open.\n");
      continue;
    }

    fp = fopen(token[1], "r+");
    
    if(fp == NULL)
    {
      printf("Error: File system image not found. \n");
    }
    
    else
    {
      set_values();
      currentAddr = LBAToOffset(2);
    }  
            
}

void closeImg()
{
    if(fp == NULL)
    {
        printf("Error: File system not open.\n");
        continue;
    }

    fclose(fp);
    fp = NULL; 
}

void infoImg()
{
    if(fp == NULL)
    {
        printf("Error: File not found\n");
        continue;
    }
    
    printf("BPB_BytsPerSec(dec) : %d \nBPB_BytsPerSec(hex) : %x\n\n",BPB_BytsPerSec,BPB_BytsPerSec);
    printf("BPB_SecPerClus(dec) : %d \nBPB_SecPerClus(hex) : %x\n\n",BPB_SecPerClus,BPB_SecPerClus);
    printf("BPB_RsvdSecCnt(dec) : %d \nBPB_RsvdSecCnt(hex) : %x\n\n",BPB_RsvdSecCnt,BPB_RsvdSecCnt);
    printf("BPB_NumFATs(dec) : %d \nBPB_NumFATs(hex) : %x\n\n",BPB_NumFATs,BPB_NumFATs);
    printf("BPB_FATSz32(dec) : %d \nBPB_FATSz32(hex) : %x\n\n",BPB_FATSz32,BPB_FATSz32);
}

void listImg()
{
    if(fp == NULL)
    {
        printf("Error: No image is opened.\n");
        continue;
    }

    int offset = LBAToOffset(currentDir);
    fseek(fp, offset, SEEK_SET);
    
    for(int i =0; i<16; i++)
    {
        fread(&dirEnt[i], 32, 1, fp);

        if ((dirEnt[i].DIR_Name[0] != (char)0xe5) && (dirEnt[i].DIR_Attr == 0x1 || dirEnt[i].DIR_Attr == 0x10 || dirEnt[i].DIR_Attr == 0x20))
        {
            char *directory = malloc(11);
            memset(directory, '\0', 11);
            memcpy(directory, dirEnt[i].DIR_Name, 11);
            printf("%s\n", directory);
        }
        // if(dirEnt[i].DIR_Attr == 0x01 || dirEnt[i].DIR_Attr == 0x10 || dirEnt[i].DIR_Attr == 0x20)
        // { 
        //   if(!(dirEnt[i].DIR_Name[0] == (char)0xE5 || dirEnt[i].DIR_Name[0] == (char)0x00 || dirEnt[i].DIR_Name[0] == (char)0x05)) 
        //   {
        //     for(int j=0; j<11; j++)
        //       printf("%c",dirEnt[i].DIR_Name[j]);
        //     printf("\n");
        //   }
        // }  
    }
}        


void changeDir()
{
    if(fptr == NULL)
    {
        printf("Error: File System Image must be opened First.\n");
        continue;
    }

    int flag;



}
