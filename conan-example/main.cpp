#include"jwt-cpp/jwt.h"
#include<iostream>
#include <chrono>


int main() {

    std::string token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2MTAwMjMxNzcsImV4cCI6MTY0MTU1OTE3NywiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.5EOfHnBmpdPvRHAuVDttgJQvbFuGEF7fC4uBSXAGg6c";
    
    auto decoded = jwt::decode(token);

    for(auto& e : decoded.get_payload_claims())
        std::cout << e.first << " = " << e.second << std::endl;

}