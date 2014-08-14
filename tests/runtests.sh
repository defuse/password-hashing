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
echo "WARNING: No tests!"
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
