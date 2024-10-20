# Указываем минимально необходимую версию CMake
cmake_minimum_required(VERSION 3.10)

# Название проекта
project(FileEncryptionProject)

# Устанавливаем стандарт C++ (например, C++11)
set(CMAKE_C_STANDARD 11)

# Добавляем исполняемый файл
# Указываем путь к вашему основному исходному файлу
add_executable(encryptor main.c)

# Находим пакет OpenSSL
find_package(OpenSSL REQUIRED)

# Линкуем OpenSSL с вашим проектом
target_link_libraries(encryptor OpenSSL::SSL OpenSSL::Crypto)

# Для включения дополнительных библиотек OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})

# Устанавливаем флаги компиляции для более детального вывода
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
