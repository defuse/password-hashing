#!/bin/bash

echo "PHP"
echo "---------------------------------------------"
php tests/test.php
if [ $? -ne 0 ]; then
    echo "FAIL."
    exit 1
fi
echo "---------------------------------------------"
echo ""

echo "RUBY"
echo "---------------------------------------------"
ruby tests/test.rb
if [ $? -ne 0 ]; then
    echo "FAIL."
    exit 1
fi
echo "---------------------------------------------"
echo ""

echo "C#"
echo "---------------------------------------------"
# Compile the C# test files
cp PasswordStorage.cs ./tests
cd tests
mcs Test.cs PasswordStorage.cs
mono Test.exe
if [ $? -ne 0 ]; then
    echo "FAIL."
    # Cleanup
    rm Test.exe
    rm PasswordStorage.cs
    cd ..
    exit 1
fi
# Cleanup
rm Test.exe
rm PasswordStorage.cs
cd ..
echo "---------------------------------------------"
echo ""

echo "Java"
echo "---------------------------------------------"
# Compile the Java test files
cp ./PasswordStorage.java ./tests
cd ./tests
javac Test.java PasswordStorage.java
java Test
if [ $? -ne 0 ]; then
    echo "FAIL."
    # Cleanup
    rm PasswordStorage.java
    rm *.class
    cd ..
    exit 1
fi
# Cleanup
rm ./PasswordStorage.java
rm *.class
cd ..
echo "---------------------------------------------"
echo ""

echo "PHP<->Ruby Compatibility"
echo "---------------------------------------------"
ruby tests/testRubyPhpCompatibility.rb
if [ $? -ne 0 ]; then
    echo "FAIL."
    exit 1
fi
echo "---------------------------------------------"
echo ""

echo "PHP<->Java Compatibility"
echo "---------------------------------------------"
# Compile the Java test files
cp ./PasswordStorage.java ./tests
cd ./tests
javac JavaAndPHPCompatibility.java PasswordStorage.java
java JavaAndPHPCompatibility
if [ $? -ne 0 ]; then
    echo "FAIL."
    # Cleanup
    rm PasswordStorage.java
    rm *.class
    cd ..
    exit 1
fi
# Cleanup
rm ./PasswordStorage.java
rm *.class
cd ..
echo "---------------------------------------------"
echo ""

echo "PHP<->C# Compatibility"
echo "---------------------------------------------"
# Compile the C# test files
cp PasswordStorage.cs ./tests
cd tests
mcs CSharpAndPHPCompatibility.cs PasswordStorage.cs
mono CSharpAndPHPCompatibility.exe
if [ $? -ne 0 ]; then
    echo "FAIL."
    # Cleanup
    rm CSharpAndPHPCompatibility.exe
    rm PasswordStorage.cs
    cd ..
    exit 1
fi
# Cleanup
rm CSharpAndPHPCompatibility.exe
rm PasswordStorage.cs
cd ..
echo "---------------------------------------------"
echo ""
