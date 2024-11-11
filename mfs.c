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
#define MAX_COMMAND_SIZE 255
#define MAX_NUM_ARGUMENTS 5


//struct that represents FAT32 variables used in this program
    uint16_t BPB_BytsPerSec;
    uint8_t BPB_SecPerClus;
    uint16_t BPB_RsvdSecCnt;
    uint8_t BPB_NumFATS ;
    uint32_t BPB_FATSz32;
    uint16_t BPB_ExtFlags;
    uint32_t BPB_RootClus;
    uint16_t BPB_FSInfo;  

// int32_t currentDir;
// char formattedDir[12]; // string to obtain fully changed or formatted string
int currentAddr =-1;
int flag =0;

char *token[MAX_NUM_ARGUMENTS]; //Parsed input string separated by white space
char cmdLine[MAX_COMMAND_SIZE];//Entire string inputted by the user.


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

int LBAToOffset(int32_t sector) // function to find the starting address of a block of data given the sector number
{
  return ( ( sector - 2 ) * BPB_BytsPerSec ) + ( BPB_BytsPerSec * BPB_RsvdSecCnt ) + 
            ( BPB_NumFATS  * BPB_FATSz32 * BPB_BytsPerSec ); //returns the value of the address for that block of data
}

int16_t NextLB(uint32_t sector, FILE* fp) // function that  look up into the first FAT and return the logical block address of the block in the file.
{
    uint32_t FATAdd = (BPB_BytsPerSec * BPB_RsvdSecCnt) + (sector * 4);
    int16_t value;
    fseek(fp, FATAdd, SEEK_SET);
    fread(&value, 2, 1, fp);
    return value;
}

void set_values(FILE* fp)
{ 

    fseek(fp, 11, SEEK_SET);
    fread(&BPB_BytsPerSec, 1, 2, fp);
 
    fseek(fp, 13, SEEK_SET);
    fread(&BPB_SecPerClus, 1, 1, fp);

    fseek(fp, 14, SEEK_SET);
    fread(&BPB_RsvdSecCnt, 1, 2, fp);
 
    fseek(fp, 16, SEEK_SET);
    fread(&BPB_NumFATS , 1, 1, fp);

    fseek(fp, 36, SEEK_SET);
    fread(&BPB_FATSz32, 1, 4, fp);

    fseek(fp, 40, SEEK_SET);
    fread(&BPB_ExtFlags, 1, 2, fp);

    fseek(fp, 44, SEEK_SET);
    fread(&BPB_RootClus, 1, 4, fp);

    fseek(fp, 48, SEEK_SET);
    fread(&BPB_FSInfo, 1, 2, fp);
}

void infoImg()
{
    printf("BPB_BytsPerSec(dec) : %d \nBPB_BytsPerSec(hex) : %x\n\n",BPB_BytsPerSec,BPB_BytsPerSec);
    printf("BPB_SecPerClus(dec) : %d \nBPB_SecPerClus(hex) : %x\n\n",BPB_SecPerClus,BPB_SecPerClus);
    printf("BPB_RsvdSecCnt(dec) : %d \nBPB_RsvdSecCnt(hex) : %x\n\n",BPB_RsvdSecCnt,BPB_RsvdSecCnt);
    printf("BPB_NumFATS (dec) : %d \nBPB_NumFATs(hex) : %x\n\n",BPB_NumFATS ,BPB_NumFATS );
    printf("BPB_FATSz32(dec) : %d \nBPB_FATSz32(hex) : %x\n\n",BPB_FATSz32,BPB_FATSz32);
    printf("BPB_ExtFlags(dec) : %d \nBPB_ExtFlags(hex) : %x\n\n",BPB_ExtFlags,BPB_ExtFlags);
    printf("BPB_RootClus(dec) : %d \nBPB_RootClus(hex) : %x\n\n",BPB_RootClus,BPB_RootClus);
    printf("BPB_FSInfo(dec) : %d \nBPB_FSInfo(hex) : %x\n\n",BPB_FSInfo,BPB_FSInfo);
    

}

// void changeDir()
// {
    

//     int flag;
//     if (strcmp(token[1], "..") == 0)
//     {
//         int i;
//         for (i = 0; i < 16; i++)
//         {
//             if (strncmp(dirEnt[i].DIR_Name, "..", 2) == 0)
//             {
//                 int offset = LBAToOffset(dirEnt[i].DIR_FirstClusterLow);
//                 currentDirectory = dirEnt[i].DIR_FirstClusterLow;
//                 fseek(fp, offset, SEEK_SET);
//                 fread(&dirEnt[0], 32, 16, fp);
//                 return;
//             }
//         }
//     }
//     int offset = LBAToOffset(cluster);
//     currentDirectory = cluster;
//     fseek(fp, offset, SEEK_SET);
//     fread(&dirEnt[0], 32, 16, fp);
// }

void statImg(FILE * fp, char * token[MAX_NUM_ARGUMENTS])
{
      
    flag =0;
    char filename[12];
    memset( filename, ' ', 12 );

    if(token[1] != NULL){
        char *tok = strtok(token[1], ".");
        if (tok != NULL) {
            strncpy(filename, tok, strlen(tok) < 8 ? strlen(tok) : 8); // Protect against buffer overflow
            tok = strtok(NULL, ".");

            if (tok != NULL) {
                strncpy(filename + 8, tok, strlen(tok) < 3 ? strlen(tok) : 3); // Protect against buffer overflow
            }
        }

        filename[11] = '\0';  // Ensure null-termination

        // Convert to uppercase
        for (int i = 0; i < 11; i++) {
            filename[i] = toupper((unsigned char)filename[i]);
        }

    }

    fseek(fp,currentAddr,SEEK_SET);
    fread(&dirEnt,(sizeof(struct DirectoryEntry))*16,1,fp);
      
    for(int i=0; i<16; i++)
    {
        if( strncmp( filename, dirEnt[i].DIR_Name, 11 ) == 0 )
        {
          flag=1;
          printf("Attributes: Ox%x\n",dirEnt[i].DIR_Attr);
          printf("Starting Cluster No: 0x%x\n",dirEnt[i].DIR_FirstClusterLow);
          if(dirEnt[i].DIR_Attr == 0x10)
            printf("Size: 0\n");
          else 
            printf("Size: %d\n",dirEnt[i].DIR_FileSize);
        }
    }

    if(flag == 0)
    printf("Error: File not found.\n");    
}

int main() {
    char *cmdLine = (char*) calloc(1, MAX_COMMAND_SIZE); // Use calloc to initialize to zero
    if (cmdLine == NULL) {
        perror("Failed to allocate cmdLine");
        return EXIT_FAILURE;
    }

    FILE *fp = NULL; // File pointer for opening files

    while (1) {
        printf("mfs> ");
        fflush(stdout); // Ensure "mfs> " is printed immediately

        if (!fgets(cmdLine, MAX_COMMAND_SIZE, stdin)) {
            if (feof(stdin)) { // End of file (user pressed Ctrl+D)
                printf("\nExiting...\n");
                break;
            }
            continue; // In case fgets fails but not EOF
        }

        // Strip newline character which might affect file opening
        cmdLine[strcspn(cmdLine, "\n")] = 0;

        char *token[MAX_NUM_ARGUMENTS] = {0};
        int tokenCount = 0;
        char *argPtr;
        char *currentString = strdup(cmdLine); // Duplicate the command line

        if (currentString == NULL) {
            perror("Failed to duplicate cmdLine");
            break;
        }

        // Tokenize the input strings with whitespace used as the delimiter
        while ((argPtr = strsep(&currentString, WHITESPACE)) != NULL && tokenCount < MAX_NUM_ARGUMENTS) {
            if (strlen(argPtr) > 0) {
                token[tokenCount] = strdup(argPtr);
                if (token[tokenCount] == NULL) {
                    perror("Failed to duplicate token");
                    break; // Break the loop in case of error
                }
                tokenCount++;
            }
        }

        // Process commands
        if (tokenCount > 0 && strcmp(token[0], "open") == 0) {
            if (tokenCount < 2) {
                printf("Need more arguments for 'open'.\n");
            } else {
                printf("Attempting to open: %s\n", token[1]);
                fp = fopen(token[1], "r+");
                if (fp != NULL) {
                    set_values(fp);
                    currentAddr = LBAToOffset(BPB_RootClus);
                    printf("File opened successfully.\n");
                } else {
                    printf("Failed to open file: %s\n", token[1]);
                }
            }
        }else if (strcmp(token[0], "close") == 0){
            if(fp == NULL){
                printf("FIle not open.\n");
            }else{
                fclose(fp);
                fp = NULL;
                printf("FIle closed successfully.\n");
            }
        }else if (strcmp(token[0], "exit") == 0 || (strcmp(token[0], "quit") == 0)){
            for (int i = 0; i < tokenCount; i++) {
             free(token[i]);
            }
            free(currentString);
            break;
        }else if (strcmp(token[0], "info") == 0){
            if(fp!= NULL){
                infoImg();
            }else{
                printf("ImageFile not opened.\n");
            }
        }else if (strcmp(token[0], "stat") == 0){
            if(fp== NULL)
            {
                printf("Error: File System Image must be opened First.\n");
            }else{
                if(tokenCount < 2){
                 printf("Usuage: stat <filename> \n");
                }else{
                    if(token[1] != NULL){
                      statImg(fp, token);  
                    }
                    
                }
            }
            
        }

        // Free each token and the currentString
        for (int i = 0; i < tokenCount; i++) {
            free(token[i]);
        }
        free(currentString);
    }

    free(cmdLine); // Finally free the cmdLine
    if (fp != NULL) {
        fclose(fp);
    }
    return 0;
}


// void listDir()
// {
//     if(fp == NULL)
//     {
//         printf("Error: No image is opened.\n");
//         continue;
//     }

//     int offset = LBAToOffset(currentDir);
//     fseek(fp, offset, SEEK_SET);
    
//     for(int i =0; i<16; i++)
//     {
//         fread(&dirEnt[i], 32, 1, fp);

//         if ((dirEnt[i].DIR_Name[0] != (char)0xe5) && (dirEnt[i].DIR_Attr == 0x1 || dirEnt[i].DIR_Attr == 0x10 || dirEnt[i].DIR_Attr == 0x20))
//         {
//             char *directory = malloc(11);
//             memset(directory, '\0', 11);
//             memcpy(directory, dirEnt[i].DIR_Name, 11);
//             printf("%s\n", directory);
//         }
// }        






// void exec()
// {

// }


