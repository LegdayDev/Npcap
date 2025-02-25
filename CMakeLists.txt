# CMake 최소 버전 요구사항 설정 - 3.15 이상 버전이 필요함
cmake_minimum_required(VERSION 3.15)

# 프로젝트 이름을 변수로 설정
set(PROJECT_NAME "Npcap")

# 프로젝트 설정에 변수 사용
project(${PROJECT_NAME} C)

# C11 표준을 사용하도록 설정
set(CMAKE_C_STANDARD 11)

# C11 표준 사용을 필수로 지정 (이전 버전으로 폴백하지 않음)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 실행 파일 생성 설정
add_executable(${PROJECT_NAME}
#        PcapRead.c
        Ip.c
#        Ethernet.c
)

# Npcap 헤더 파일 위치 지정
target_include_directories(${PROJECT_NAME} PRIVATE "C:/npcap/Include")

# Npcap 라이브러리 파일 위치 지정 (64비트 버전)
target_link_directories(${PROJECT_NAME} PRIVATE "C:/npcap/Lib/x64")

# 필요한 라이브러리 링크 설정
target_link_libraries(${PROJECT_NAME}
        PRIVATE
        wpcap
        delayimp
)

# 지연 로딩 설정
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/DELAYLOAD:wpcap.dll")