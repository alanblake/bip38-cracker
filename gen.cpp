#include<iostream>

using namespace std;

int main(int argc, char** argv) {
    string a = argv[1];
    while(true) {
        cout<<a<<endl;
        for(int i = 0; i < a.size(); i++) {
            if(a[i] == 'z')
                a[i] = 'a';
            else {
                a[i]++;
                break;
            }
        }
    }
}
