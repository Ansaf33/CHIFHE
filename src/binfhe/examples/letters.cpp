
#include "binfhecontext.h"
#include <iostream>
#include <string.h>
#include <typeinfo>
#include <bitset>
using namespace lbcrypto;

// LETTER TO BINARY 8 BITS


string LTB(string s){
    
    int n = (int)s.length();
    
    string fin;
     
        for (int i = 0; i < n; i++)
        {
            int val = int(s[i]);
     
            string bin = "";
            while (val > 0)
            {
                (val % 2)? bin.push_back('1') :
                           bin.push_back('0');
                val /= 2;
            }
            reverse(bin.begin(), bin.end());
            
            while(bin.size() != 8 ){
                bin.insert(bin.begin(),'0');
            }
     
            fin+=bin;
        }
    return fin;
}

char binaryStringToChar(const std::string& binaryString) {
    if (binaryString.length() != 8) {
        throw std::invalid_argument("Binary string must be 8 bits long");
    }

    std::bitset<8> bitset(binaryString);
    return static_cast<char>(bitset.to_ulong());
}



int main(){
    
    
    
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128);
    
    // mock values
    auto mock_sk = cc.KeyGen();
    cc.BTKeyGen(mock_sk);
    auto mock_encrypted_0 = cc.Encrypt(mock_sk,0);
    auto mock_encrypted_1 = cc.Encrypt(mock_sk,1);
    auto mock_encrypted_2 = cc.Encrypt(mock_sk,2);
    auto mock_encrypted_3 = cc.Encrypt(mock_sk,3);
    
    LWEPlaintext zero;
    LWEPlaintext one;
    LWEPlaintext two;
    LWEPlaintext three;
    cc.Decrypt(mock_sk,mock_encrypted_0,&zero);
    cc.Decrypt(mock_sk,mock_encrypted_1,&one);
    cc.Decrypt(mock_sk,mock_encrypted_2,&two);
    cc.Decrypt(mock_sk,mock_encrypted_3,&three);
    
    
    // define the vectors and types
    vector<pair<decltype(mock_sk),decltype(mock_encrypted_0)>>sken;
    
    // ENCRYPT 0
    
    
    printf("Enter message to encrypt : ");
    string message;
    getline(cin, message);
    string binary = LTB(message);

    
    
    // THE VECTOR SKEN STORES { SECRET KEY , ENCRYPTED CIPHERTEXT } IN IT
    
    
    for(int i=0;i<binary.size();i++){
        
        int bit = binary[i] - 48;

        auto sk = cc.KeyGen();
 
        
        cc.BTKeyGen(sk);
     
        // encrypt using public key
        auto plain = cc.Encrypt(sk,bit);
        sken.push_back({sk,plain});
    }
    
    printf("Ciphertext and Secret Keys are\n");
    for(int i=0;i<sken.size();i++){
        cout << sken[i].second << " " << sken[i].first << endl;
    }
    
    // DECRYPTED DATA
    vector<LWEPlaintext>dec;
    
    
    
    for(int i=0;i<sken.size();i++){
        LWEPlaintext decrypted_bit;
        cc.Decrypt(sken[i].first,sken[i].second,&decrypted_bit);
            dec.push_back(decrypted_bit);
    }
    
    printf("Decrypted bits = ");
    
    for( auto x:dec){
        cout << x;
    }
    printf("\n");
    
    
    // CONVERT IT BACK TO PLAINTEXT FORM
    string decrypted_final;
    
    
    
    
    for(int i=0;i<dec.size();i+=8){
        string singleByte;
        for(int k=i;k<i+8;k++){
            if( dec[k] == zero ){
                singleByte.push_back('0');
            }
            else{
                singleByte.push_back('1');
            }
        }
        
        if( singleByte.size() == 8 ){
            decrypted_final.push_back(binaryStringToChar(singleByte));
        }
        
    }
    
    printf("Decrypted value is = ");
    
    cout << decrypted_final << endl;
    
    
    

    
    return 0;
    
}
