#include <iostream>
#include <iomanip>
#include <string>
#include <fstream>
#include <unordered_map>
#include <cstdlib>
#include <cctype>
using std::cin;
using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::ifstream;
using std::ofstream;
using std::istream;
using std::ostream;
using std::unordered_map;
using std::setw;
using std::left;
using std::right;
using std::fixed;
using std::setprecision;
 
typedef unsigned long ulong;
 
struct credentials {
    void set_salt(string &);
    void set_hash(string &);
 
    void operator=(const credentials &);
    bool operator==(const credentials &);
 
    string salt;
    ulong password_hash;
};
 
void credentials::set_salt(string &username) { // this function uses the "sometimes" salt to generate different salt values for every instance that 2 passwords are the same. If the resulting value is not readable it prints the '?' character instead.
 
    salt = "S0m3t1M3$";
 
for (int i = 0; i < (int)salt.size(); i++) {
 
char c = salt[i] + (username[i % username.size()] & 0x7);
 
if (std::isprint((unsigned char)c))
salt[i] = c;
else
 salt[i] = '?';
    }
}
 
void credentials::set_hash(string &password) { // this function builds a hash code that from the garbled salt value and stores that hash code in the variable password_hash. This makes it harder for a hypothetical password to be stolen because the plain password format is changed. 
 string combined = password + salt;
 
 ulong H = 0;
 
for (int i = 0; i < (int)combined.size(); i++) {
 H = ((H << 5) | (H >> 59)) + combined[i];
 }
 
 password_hash = H;
}
 
void credentials::operator=(const credentials &rhs) {
salt = rhs.salt;
password_hash = rhs.password_hash;
}
 
bool credentials::operator==(const credentials &rhs) {
return password_hash == rhs.password_hash;
}
 
istream &operator>>(istream &in, credentials &login) {
in >> login.salt;
in >> std::hex >> login.password_hash;
in >> std::dec;
 return in;
}
 
ostream &operator<<(ostream &out, const credentials &login) {
 out << setw(10) << left << login.salt << " ";
 out << std::hex << login.password_hash;
 out << std::dec;
  return out;
}
 
typedef unordered_map<string, credentials> hashtable;
 
void write_hashtable(hashtable &H, bool verbose) { // This function saves the hashtable to the password.txt file. Every username and password gets paired, a hash gets computed, and stores the hash value under the username. Every entry gets written in the txt file.
 string username;
string password;
 
for (;;) {
 
if (verbose) {
 
cout << "** S = "
<< setw(4) << H.size()
<< " N = "
<< setw(4) << H.bucket_count()
<< " : load = "
<< fixed << setprecision(2)
<< H.load_factor()
<< endl;
 }
 
if (!(cin >> username >> password))
        break;
 
 credentials login;
  login.set_salt(username);
  login.set_hash(password);
  H[username] = login;
    }
  ofstream fout("passwd.txt");
 
    if (!fout) {
        cerr << "Unable to open passwd.txt" << endl;
        exit(1);
    }
 
    hashtable::iterator p;
 
    for (p = H.begin(); p != H.end(); p++) {
  fout << setw(10) << left << p->first << " "
<< p->second << endl;
    }
 
fout.close();
 
if (verbose) {
 
 cout << endl;
 for (unsigned int i = 0; i < H.bucket_count(); i++) {
 cout << setw(6) << i << " "
 << setw(4) << H.bucket_size(i);
 hashtable::local_iterator q;
 for (q = H.begin(i); q != H.end(i); q++) {
cout << " " << q->first;
 }
  cout << endl;
        }
 cout << endl;
    }
}
 
void read_hashtable(hashtable &H, bool verbose) { // This funtion rebuilds the hash table from the txt file then reads and stores each line under the username. This function allows the verbose option to print the resized information.
 
ifstream fin("passwd.txt");
 
if (!fin) {
cerr << "Unable to open passwd.txt" << endl;
exit(1);
    }
 
string username;
credentials login;
 
for (;;) {
  if (verbose) {
 
 cout << "** S = "
 << setw(4) << H.size()
<< " N = "
<< setw(4) << H.bucket_count()
<< " : load = "
<< fixed << setprecision(2)
 << H.load_factor()
 << endl;
        }
 
if (!(fin >> username >> login))
break;
 
H[username] = login;
}
 fin.close();
 if (verbose) {
  cout << endl;
 for (unsigned int i = 0; i < H.bucket_count(); i++) {
 cout << setw(6) << i << " "
 << setw(4) << H.bucket_size(i);
 hashtable::local_iterator q;
 for (q = H.begin(i); q != H.end(i); q++) {
 cout << " " << q->first;
            }
 
  cout << endl;
        }
 
        cout << endl;
    }
}
 
int main(int argc, char *argv[]) {
 
    bool create_mode = false;
    bool check_mode = false;
    bool verbose = false;
    float load = 1.0;
 
    for (int i = 1; i < argc; i++) { // optional command line arguments.
 
        string arg = argv[i];
 
        if (arg == "-create")
            create_mode = true;
 
        else if (arg == "-check")
            check_mode = true;
 
        else if (arg == "-verbose")
            verbose = true;
 
        else if (arg == "-load" && i + 1 < argc)
            load = atof(argv[++i]);
 
        else {
            cerr << "usage: " << argv[0]
                 << " -create|-check [-load Z] [-verbose] < logins.txt" << endl;
            return 1;
        }
    }
 
    if (!create_mode && !check_mode) { // this option only prints usage if given no arguments.
        cerr << "usage: " << argv[0]
             << " -create|-check [-load Z] [-verbose] < logins.txt" << endl;
        return 1;
    }
 
    if (!(load > 0.0 && load <= 1.0)) {  // this option checks if load value is between 0 and 1.
        cerr << "error: -load value must be > 0.0 and <= 1.0" << endl;
        return 1;
    }
 
    hashtable H;
    
    H.max_load_factor(load);
 
    if (create_mode) {  // this writes the password.txt file from the hashtable.
   write_hashtable(H, verbose);
    }
 
    else if (check_mode) { // This check is to see if every written username or password should have access or not.
 
    read_hashtable(H, verbose);
   string username;
   string password;
   while (cin >> username >> password) {
 
            hashtable::iterator p = H.find(username);
 
            if (p == H.end()) {
                cout << setw(10) << left << username << " bad username" << endl;
                continue;
            }
            credentials login = p->second;
            credentials test;
            test.salt = login.salt;
            test.set_hash(password);
 
            if (login == test)
                cout << setw(10) << left << username << " access granted" << endl;
            else
                cout << setw(10) << left << username << " bad password" << endl;
        }
    }
 
    return 0;
}