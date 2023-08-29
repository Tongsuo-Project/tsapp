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
    randnum.cpp

HEADERS += \
    home.h \
    mainwindow.h \
    randnum.h

# Default rules for deployment.
target.path = $$(PREFIX)
!isEmpty(target.path): INSTALLS += target

win32: LIBS += -ladvapi32 -lcrypt32 -lgdi32 -luser32 -lws2_32 -L$$(TONGSUO_HOME)/lib -llibcrypto
else:unix: LIBS += -L$$(TONGSUO_HOME)/lib64 -lcrypto

INCLUDEPATH += $$(TONGSUO_HOME)/include
DEPENDPATH +=  $$(TONGSUO_HOME)/include

win32-g++: PRE_TARGETDEPS += $$(TONGSUO_HOME)/lib/libcrypto.lib.a
else:win32:!win32-g++: PRE_TARGETDEPS += $$(TONGSUO_HOME)/lib/libcrypto.lib
else:unix: PRE_TARGETDEPS += $$(TONGSUO_HOME)/lib64/libcrypto.a

FORMS += \
    home.ui \
    randnum.ui

RESOURCES += \
    images.qrc
