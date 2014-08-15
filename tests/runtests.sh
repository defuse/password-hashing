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
echo "WARNING: No tests!"
echo "---------------------------------------------"
echo ""

echo "Java"
echo "---------------------------------------------"
# Compile the Java test files
cp ./PasswordHash.java ./tests
cd ./tests
javac Test.java
java Test
if [ $? -ne 0 ]; then
    echo "FAIL."
    # Cleanup
    rm Test.class
    rm PasswordHash.class
    rm PasswordHash.java
    cd ..
    exit 1
fi
# Cleanup
rm ./PasswordHash.class
rm ./PasswordHash.java
rm ./Test.class
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
