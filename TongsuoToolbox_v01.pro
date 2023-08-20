QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    home.cpp \
    main.cpp \
    mainwindow.cpp \
    randnum.cpp \
    sm2encrypt.cpp

HEADERS += \
    home.h \
    mainwindow.h \
    randnum.h \
    sm2encrypt.h

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

INCLUDEPATH += Tongsuo\include
INCLUDEPATH += Tongsuo\providers\implementations\include
INCLUDEPATH += Tongsuo\providers\common\include
INCLUDEPATH += Tongsuo\apps\include
INCLUDEPATH += Tongsuo\crypto\include

win32: LIBS += -L$$PWD/Tongsuo/ -lcrypto

INCLUDEPATH += $$PWD/Tongsuo
DEPENDPATH += $$PWD/Tongsuo

win32:!win32-g++: PRE_TARGETDEPS += $$PWD/Tongsuo/crypto.lib
else:win32-g++: PRE_TARGETDEPS += $$PWD/Tongsuo/libcrypto.a

FORMS += \
    home.ui \
    randnum.ui \
    sm2encrypt.ui

RESOURCES += \
    images.qrc
