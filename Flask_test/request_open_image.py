from PIL import Image
from io import BytesIO
import requests
r = requests.get('https://gss0.baidu.com/9vo3dSag_xI4khGko9WTAnF6hhy/zhidao/pic/item/58ee3d6d55fbb2fbe2e6e275494a20a44723dc8c.jpg')
i = Image.open(BytesIO(r.content))
i.show()