python3 -m venv /venv-test
/venv-test/bin/pip install pymysql[rsa]
/venv-test/bin/python -c "import pymysql; connection = pymysql.connect(host=\"0.0.0.0\",user=\"wordpress\",password=\"wordpress\",database=\"wordpress\",port=3306,cursorclass=pymysql.cursors.DictCursor); print(connection.cursor().execute(\"SELECT * FROM wp_posts\"))"
