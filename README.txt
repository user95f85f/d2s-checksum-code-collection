static int d2charsave_checksum(unsigned char const *data, unsigned int len, unsigned int offset){
  int checksum;
  unsigned int i;
  unsigned int ch;

  if (!data) return 0;
  checksum=0;
  for (i=0; i<len; i++) {
    ch=data[i];
    if (i>=offset && i<offset+sizeof(int)) ch=0;
    ch+=(checksum<0);
    checksum=2*checksum+ch;
  }
  return checksum;
} 
unsigned int uiCS = 0;
for ( int i = 0; i < iSize; ++i )
uiCS = (uiCS<<1) + pucData[i] + ( uiCS & 0x80000000 ? 1 : 0 );
// pucData - pointer to the byte stream of the .d2s file
// iSize - number of bytes in the stream ( filesize )
DWORD Checksum( unsigned char *pucData, int iSize )
{
    // delete old checksum at offset 0x0C
    *((unsigned int*)(pucData+12)) = 0;

    // init new checksum with 0
    unsigned int uiCS = 0;

    // this is the whole checksum calculation
    for ( int i = 0; i < iSize; ++i )
        uiCS = (uiCS<<1) + pucData[i] + ( uiCS & 0x80000000 ? 1 : 0 );

    // write new checksum to stream
    *((unsigned int*)(pucData+12)) = uiCS;
    return uiCS;
}

void __fastcall DUMPER_FixChecksum(BYTE* pFile, DWORD dwSize)
{
   if (pFile == 0 || dwSize < 0)
      return;

   DWORD* pSignature = (DWORD*)(pFile+0xC);
   *pSignature = 0;
   
   int nSignature = 0;
   for (DWORD i = 0; i < dwSize; i++) {
      int byte = pFile[i];
      if (nSignature < 0)
         byte++;
      nSignature = byte + nSignature * 2;
   }
   *pSignature = nSignature;
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Diablo2FileFormat
{
    public class Checksum
    {
        public static void UpdateChecksum(byte[] fileData, int checkSumOffset)
        {
            if (fileData == null || fileData.Length < checkSumOffset + 4) return;

            // Clear out the old checksum
            Array.Clear(fileData, checkSumOffset, 4);

            int[] checksum = new int[4];
            bool carry = false;

            for (int i = 0; i < fileData.Length; ++i)
            {
                int temp = fileData[i] + (carry ? 1 : 0);

                checksum[0] = checksum[0] * 2 + temp;
                checksum[1] *= 2;

                if (checksum[0] > 255)
                {
                    checksum[1] += (checksum[0] - checksum[0] % 256) / 256;
                    checksum[0] %= 256;
                }

                checksum[2] *= 2;

                if (checksum[1] > 255)
                {
                    checksum[2] += (checksum[1] - checksum[1] % 256) / 256;
                    checksum[1] %= 256;
                }

                checksum[3] *= 2;

                if (checksum[2] > 255)
                {
                    checksum[3] += (checksum[2] - checksum[2] % 256) / 256;
                    checksum[2] %= 256;
                }

                if (checksum[3] > 255)
                {
                    checksum[3] %= 256;
                }

                carry = (checksum[3] & 128) != 0;
            }

            for (int i = checkSumOffset; i < checkSumOffset + 4; ++i)
            {
                fileData[i] = (byte)checksum[i - checkSumOffset];
            }
        }
    }
}
package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/sqweek/dialog"
)

func main() {
	file, err := dialog.File().Title("Choose Save to fix").Filter("Diablo 2 Save File", "d2s").Load()

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println(err)
		return
	}

	binary.LittleEndian.PutUint32(data[12:], uint32(0))

	//Generate Checksum
	var sum int32 = 0
	for _, byt := range data {
		var bytcopy int32 = int32(byt)
		if sum < 0 {
			bytcopy += 1
		}
		sum = bytcopy + (sum * 2)
	}

	binary.LittleEndian.PutUint32(data[12:], uint32(sum))

	f, err := os.Create(file)
	if err != nil {
		fmt.Println(err)
		return
	}

	n2, err := f.Write(data)
	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	}

	fmt.Println(n2, "bytes written successfully to "+file)
	err = f.Close()
	if err != nil {
		fmt.Println(err)
		return
	}

	log.Println("exiting...")
}
$/=\1;while(<>){$c=($c<<1)+($c>>31)+($x>>2==3?0:ord);$x++}printf"%x",$c
from BitsAndBytes import *

readFrom = open('E:\\Diablo II\\save\\test.d2s','rb')
fileLength = len(readFrom.read())
bytes = []
for i in range(0,fileLength):
    readFrom.seek(0)
    readFrom.seek(i)
    data = readFrom.read(1)
    bytes.append(data)
a1 = 0
a2 = 0
a3 = 0
a4 = 0
b = 0
bytes[12] = 0
bytes[13] = 0
bytes[14] = 0
bytes[15] = 0

for c in bytes:
    a1 = (a1 << 1) + b + BinaryToDecimal(HexToBinary(ByteToHex(str(c))))
    a2 <<= 1

    a2 += (a1 >> 8)
    a1 = a1 & 255

    a3 <<= 1
    a3 +=  (a2 >> 8)
    a2 = a2 & 255
         
    a4 <<= 1
    a4 += (a3 >> 8)
    a3 = a3 & 255
    a4 = a4 & 255
           
    if (a4 & 0x80) <> 0:
        b = 1
    else:
        b = 0

print BinaryToHex(DecimalToBinary(a1,8))
print BinaryToHex(DecimalToBinary(a2,8))
print BinaryToHex(DecimalToBinary(a3,8))
print BinaryToHex(DecimalToBinary(a4,8))
'calculate checksum for d2s file
Public Sub UpdateChecksum()

Dim lCharFileLen As Long

Dim i As Long 'just for counting
Dim a1 As Integer '1st byte of DWORD
Dim a2 As Integer '2nd byte of DWORD
Dim a3 As Integer '3rd byte of DWORD
Dim a4 As Integer '4th byte of DWORD
Dim b As Byte 'could be 0 or 1, see the code
Dim d As Integer  'precalculation

' Character bytes stored in gbytArray(), starting at 1
' positions 13 - 16 are where the checksum was in the original .d2s file,
' but these 4 bytes must NOT be used in the calculation of the new checksum

 gbytArray(13) = 0
 gbytArray(14) = 0
 gbytArray(15) = 0
 gbytArray(16) = 0

 ' local variables initialization
 b = 0
 d = 0
 a1 = 0
 a2 = 0
 a3 = 0
 a4 = 0
 lCharFileLen = gCharacter.FileSize 'total number of bytes in Character "d2s" file

 ' loop over the total file contents
 For i = 1 To lCharFileLen
  ' get the bytes and add overflow (b)
  d = CInt(gbytArray(i)) + b
  ' begining of the checksum calculation
  a1 = (a1 * 2) + d
  a2 = a2 * 2
  ' overflow control
  If a1 > 255 Then
   a2 = a2 + CInt((a1 - (a1 Mod 256)) / 256)
   a1 = a1 Mod 256
  End If
  a3 = a3 * 2
  ' overflow control
  If a2 > 255 Then
   a3 = a3 + CInt((a2 - (a2 Mod 256)) / 256)
   a2 = a2 Mod 256
  End If
  a4 = a4 * 2
  ' overflow control
  If a3 > 255 Then
   a4 = a4 + CInt((a3 - (a3 Mod 256)) / 256)
   a3 = a3 Mod 256
  End If
  ' overflow control
  If a4 > 255 Then
   a4 = a4 Mod 256
  End If
        
  ' simulating the "setl bl" - ASM code
  If ((a4 And &H80) <> 0) Then
   b = 1
  Else
   b = 0
  End If
 Next i

 'done, so put the new checksum back into the Char byte array
 gbytArray(13) = CByte(a1)
 gbytArray(14) = CByte(a2)
 gbytArray(15) = CByte(a3)
 gbytArray(16) = CByte(a4)
End Sub


func FixCheckSum()
dim $checksum[4]
$byteA[12]=0x00
$byteA[13]=0x00
$byteA[14]=0x00
$byteA[15]=0x00
$boolCarry=0
for $i=0 to UBound($byteA)-1
$temp=Dec(Hex(Binary($byteA[$i])))+$boolCarry
$checksum[0]= $checksum[0]*2 +$temp
$checksum[1]=$checksum[1]*2
if $checksum[0] > 255 Then
$checksum[1] = $checksum[1] + ($checksum[0] - Mod($checksum[0],256)) / 256
$checksum[0] = Mod($checksum[0],256)
EndIf
$checksum[2]=$checksum[2]*2
if $checksum[1] > 255 Then
$checksum[2] = $checksum[2] + ($checksum[1] - Mod($checksum[1],256)) / 256
$checksum[1] = Mod($checksum[1],256)
EndIf
$checksum[3]=$checksum[3]*2
if $checksum[2] > 255 Then
$checksum[3] = $checksum[3] + ($checksum[2] - Mod($checksum[2],256)) / 256
$checksum[2] = Mod($checksum[2],256)
EndIf
If $checksum[3] > 255 Then
$checksum[3] = Mod($checksum[3], 256)
EndIf
if BitAND($checksum[3],0x80)<>0 Then
$boolCarry=1
Else
$boolCarry=0
EndIf
Next
$byteA[12]="0x"&Hex($checksum[0],2)
$byteA[13]="0x"&Hex($checksum[1],2)
$byteA[14]="0x"&Hex($checksum[2],2)
$byteA[15]="0x"&Hex($checksum[3],2)
EndFunc
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
char const *d2sfile =
"C:\\Users\\user1\\AppData\\Local\\VirtualStore\\Program Files (x86)\\Diablo II\\Save\\my_d.d2s";
#else
char const *d2sfile =
"/home/xubuntu/.wine/drive_c/Program Files (x86)/Diablo II/Save/my_d.d2s";
#endif

int main(void){
  FILE *f;
  long fsize;
  char *all;
  int ct;
  int c = 0;
  int addr;
  int add;
  /*printf("Your d2s file: %s\n", d2sfile);
  getchar();*/
  f = fopen(d2sfile, "rb");
  if(f == NULL){
    puts("ERROR: Could not open your d2s file.");
    return 1;
  }
  fseek(f, 0, SEEK_END);
  fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  all = malloc(fsize);
  fread(all, fsize, 1, f);
  fclose(f);
  for(addr=0; addr < fsize; addr++){
    ct = all[addr] & 0xFF;
    if(c < 0) ct++;
    add = 0;
    if((addr >> 2) != 3)
      add = ct;
    c = (c << 1) + add;
  }
  free(all);
  c = (c & 0xff000000) >> 24 | (c & 0xff0000) >> 8 | (c & 0xff00) << 8 | (c & 0xff) << 24;
  printf("checksum: %08X\n", c);
  return 0;
}
#include <iostream>
#include <fstream>
#include <iomanip>
using namespace std;

#ifdef _WIN32
char const *d2sfile =
"C:\\Users\\user1\\AppData\\Local\\VirtualStore\\Program Files (x86)\\Diablo II\\Save\\my_d.d2s";
#else
char const *d2sfile =
"/home/xubuntu/.wine/drive_c/Program Files (x86)/Diablo II/Save/my_d.d2s";
#endif

int main () {
  streampos size;
  char * memblock;

  ifstream file (d2sfile, ios::in|ios::binary|ios::ate);
  if (!file.is_open()){
    cout << "unable to open your d2s file." << endl;
    return 1;
  }
  size = file.tellg();
  memblock = new char[size];
  file.seekg (0, ios::beg);
  file.read (memblock, size);
  file.close();
  //int ct = memblock[0] & 0xFF;
  //cout << "now we can read the data:" << ct << endl;
  
  int ct;
  int c = 0;
  for(int addr=0; addr<size; addr++){
    ct = memblock[addr] & 0xFF;
    if(c < 0) ct++;
    int add = 0;
    if((addr >> 2) != 3)
      add = ct;
    c = (c << 1) + add;
  }
  delete[] memblock;
  
  c = (c & 0xff000000) >> 24 | (c & 0xff0000) >> 8 | (c & 0xff00) << 8 | (c & 0xff) << 24;
  // now we convert the integer into hexadecimal.
  cout << "checksum: " << setfill ('0') << setw(8) << hex << c;
  cout << endl;
  return 0;
}using System;
using System.IO;
namespace Hello{
  class Hello{
    static void o(string _s){Console.WriteLine(_s);}
    static int Main(string[] args){
      string os = System.Environment.OSVersion.ToString();
      string d2sfile = "/home/xubuntu/.wine/drive_c/Program Files (x86)/Diablo II/Save/my_d.d2s";
      if (os.StartsWith("Microsoft Windows"))
        d2sfile = "C:\\Users\\user1\\AppData\\Local\\VirtualStore\\Program Files (x86)\\Diablo II\\Save\\my_d.d2s";

      try
      {
        FileStream fs = new FileStream(d2sfile, FileMode.Open);
        int ct;
        int c = 0;
        int addr = 0;
        while((ct = fs.ReadByte()) > -1)
        {
          if (c < 0)
          {
            //Console.WriteLine("Is negative: " + c.ToString());
            ct++;
          }
          int add = 0;
          if ((addr >> 2) != 3)
            add = ct;
          c = (c << 1) + add;
          addr++;
        }
        uint c2 = ((uint)c & 0xff000000) >> 24 | ((uint)c & 0xff0000) >> 8 | ((uint)c & 0xff00) << 8 | ((uint)c & 0xff) << 24;
        string chksum = c2.ToString("X8");
        o("Checksum: " + chksum);
        //Console.WriteLine("Checksum: " + chksum.Substring(6, 2) + chksum.Substring(4, 2) 
        //  + chksum.Substring(2, 2) + chksum.Substring(0, 2));
      }
      catch (Exception ex)
      {
        Console.WriteLine(ex.Message);
      }
      Console.WriteLine("Press ENTER to continue/exit.");
      Console.ReadKey();
      return 0;
    }
  }
}
import java.io.*;

public class chksum{
  public static void main(String[] args){
    String os = System.getProperty("os.name");
    String d2sfile = 
"/home/xubuntu/.wine/drive_c/Program Files (x86)/Diablo II/Save/my_d.d2s";
    if(!os.equals("Linux"))
      d2sfile = 
"C:\\Users\\user1\\AppData\\Local\\VirtualStore\\Program Files (x86)\\Diablo II\\Save\\my_d.d2s";

    File f = new File(d2sfile);
    if(!f.exists() || !f.canRead()){
      o("Your d2s file doesn't exist! Youch!");
      return;
    }

    FileInputStream fis;
    try{
      fis = new FileInputStream(f);
    }
    catch(Exception ex){
      o("what....the...FUCK.");
      return;
    }

    int toread = 0;
    try{
      toread = fis.available();
    }
    catch(Exception ex){
      o("Sorry folks. can't read your stupid d2s file.");
      return;
    }
    byte[] all = new byte[toread];
    try{
      if(fis.read(all) != toread){
        o("FUCK YOU JAVA");
        return;
      }
      fis.close();
    }
    catch(Exception ex){
      ex.printStackTrace();
      return;
    }
    //o(Integer.toString(ub(all[0])));
    
    int ct;
    int c = 0;
    for(int addr=0; addr<toread; addr++){
      ct = ub(all[addr]);
      if(c < 0) ct++;
      int add = 0;
      if((addr >> 2) != 3)
        add = ct;
      c = (c << 1) + add;      
    }
    c = (c & 0xff000000) >> 24 | (c & 0xff0000) >> 8 | (c & 0xff00) << 8 | (c & 0xff) << 24;
    String chksum = Integer.toHexString(c).toUpperCase();
    while(chksum.length() < 8)  //pad that shit. just in case.
      chksum = "0" + chksum;
    /*chksum = chksum.substring(6, 8) +
             chksum.substring(4, 6) +
             chksum.substring(2, 4) +
             chksum.substring(0, 2);
    */
    o("Checksum: " + chksum);
  }
  public static int ub(byte _b) { return _b & 0xFF; }
  private static void o(String _o){ System.out.println(_o); }
}
#!/usr/bin/python3
from sys import platform
from os import path
from struct import unpack, pack
import sys
import binascii

d2sfile = '/home/xubuntu/.wine/drive_c/Program Files (x86)/Diablo II/Save/my_d.d2s'
if platform != 'linux':
  d2sfile = 'C:\\Users\\user1\\AppData\\Local\\VirtualStore\\Program Files (x86)\\Diablo II\\Save\\my_d.d2s'
if not path.isfile(d2sfile):
  print("your d2s file does not exist.")
  exit(1)
all = ''
try:
  myfile = open(d2sfile, mode='rb')
  all = myfile.read()
  myfile.close()
except:
  print(sys.exc_info()[0])
  exit(2)
#print(len(all))
c = 0
for addr in range(len(all)):
  ct = ord(all[addr:addr+1])
  ct += c >> 31 & 1
  add = 0
  if (addr >> 2) != 3:
    add = ct
  c = add + (c << 1)

"""
if c > 2147483647:
  c = c & 2147483647
if c < -2147483648:
  c = c * -1
  c = c & 2147483647
  c = c * -1
"""
#print(binascii.hexlify(pack('i', c)))
#c=255
c = (c & 0xff000000) >> 24 | (c & 0xff0000) >> 8 | (c & 0xff00) << 8 | (c & 0xff) << 24
chksum = '{0:08X}'.format(c)
print('Checksum:', chksum)
#print(backwards_chksum)
#print('Checksum:', backwards_chksum[6:8] + backwards_chksum[4:6] + backwards_chksum[2:4] + backwards_chksum[0:2])
#print(ord(all[37:38]))
#myfile.seek(37)
#out = myfile.read(1)
#print(unpack('I', out))
#print(ord(out))
use warnings;
use strict;
use File::Copy;
use feature 'say';
use myconfig qw/read_config/;

my $D2sDataFile = read_config();

if(! -f $D2sDataFile){
  die "$D2sDataFile does not exist! Where can we get the checksum?";
}

my $all;
{
  local $/;
  open(my ${f}, '<', $D2sDataFile);
  $all = <$f>;
  close(${f});
}

#say 'in file checksum: ', +(unpack('H8', &get_actual_checksum()))[0];
say 'in file checksum: ', uc(&get_actual_checksum());
say 'my checksum:      ', sprintf('%08X', &get_your_checksum());

sub get_actual_checksum(){
  #CORE::say +(unpack('H32', $all))[0];
  #return pack('H*', substr((unpack('H32', $all))[0], 24, 8));
  return unpack('H*', substr($all, 12, 4));
}

sub get_your_checksum(){
  my $c = 0;
  my $addr = 0;
  my @cs = unpack('C*', $all);
  for my $ct(@cs){
    $ct += $c >> 31 & 1;
    $c = (($addr >> 2 == 3) ? 0 : $ct) + ($c << 1);
    $addr++;
  }
  return ($c & 0xff000000) >> 24 | ($c & 0xff0000) >> 8 | ($c & 0xff00) << 8 | ($c & 0xff) << 24;
}
use warnings;
use strict;
my $c = 0;  #checksum
my $loc = 0;
open(my ${f}, '<', 'aTotal_Bitch.d2s') or die $!;
while(sysread(${f}, my $s, 1)){
  my ($byte) = unpack('C', $s);
  $byte = 0 if($loc == 12 || $loc == 13 || $loc == 14 || $loc == 15);
  $byte++ if($c < 0);
  $c = $byte + $c * 2;
  ($c) = unpack('l', pack('l', $c));
  $loc++;
}
printf("Calculated checksum: %s\n", unpack('H8', pack('L', $c)));

use warnings;
use strict;
my $c = 0;  #checksum
my $loc = 0;
open(my ${f}, '<', 'aTotal_Bitch.d2s') or die $!;
while(sysread(${f}, my $s, 1)){
  my ($byte) = unpack('C', $s);
  if($loc == 12 || $loc == 13 || $loc == 14 || $loc == 15){
    if($loc == 12){
      print "Original checksum: ";
    }
    printf '%X', $byte; #or: print unpack('H2', $s);
    if($loc == 15){
      print "\n";
    }
    $byte = 0;
  }
  if($c < 0){
    $byte++;
  }
  $c = $byte + $c * 2;
  undef $byte;
  ($c) = unpack('l', pack('l', $c));
  $loc++;
}
undef $loc;
close ${f};
printf("Calculated checksum: %s\n", unpack('H8', pack('L', $c)));
undef $c;

