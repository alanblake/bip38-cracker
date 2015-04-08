#include<iostream>

using namespace std;

int main(int argc, char** argv) {
    string a = argv[1];
    while(true) {
        cout<<a<<endl;
        for(int i = a.size()-1; i >= 0; i--) {
            if(a[i] == 'z')
                a[i] = 'a';
            else {
                a[i]++;
                break;
            }
        }
    }
}
