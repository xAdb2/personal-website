---
title: 'AIS3 Pre-exam 2024'
published: 2024-05-25
draft: false
tags: ['CTF', 'Writeup']
toc: true
---

## Misc

### Welcome

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_92bec447281e13623e3618dbe2b3670a.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1761158616&Signature=DtO6qyJ3EN4hYWU8Fvwdbj4z75U%3D)

:::flag
AIS3{Welc0me_to_AIS3_PreExam_2o24!}
:::

### Quantum Nim Heist

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_d08232c4b291636fbb1e0d418b15e54b.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1761158582&Signature=h28AG7bsSasxGc2FPBel9joFGPQ%3D)

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_45a6445ea06c4aa01d9da76a50ab4612.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1761158654&Signature=kIr02P8sRPraH3099dvnYnR7q1U%3D)

題目使用`nc`連線。可以看到這是一個拿石頭的遊戲。
- 每次選擇一列跟拿幾顆石頭。
- 最後一個沒有石頭拿的人就會輸遊戲。
- 目標讓電腦拿不到石頭。
- `正常玩遊戲一定贏不了電腦。`

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_b8b6d0a228772a1c024ede1c3bbdcb9a.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1761158928&Signature=JeOwyvT4VElXfOLK4hhdBZstYm8%3D)

輸入超過當前的列數，跳出這是非法的操作。

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_fdfeeb5fa20557fb60799233942c6e3b.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1761160969&Signature=%2FBZfBLUtwm9O0eVJBEsSJxDzCHM%3D)

發現可以有數字以外的輸入，這邊就一直輸入`o`直到剩最後一顆石頭我們在直接拿走就可以拿到 FLAG。

:::flag
AIS3{Ar3_y0u_a_N1m_ma57er_0r_a_Crypt0_ma57er?}
:::

### Three Dimensional Secret

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_07e36266932e560d7c4c173b42424d1f.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1761161084&Signature=F9gROPX5rnFO9I140mNlU4FFhYs%3D)

檔案下載下來後只給了一個`.pcapng`檔案。

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_d701ffc823a42554da7c2085f2a694a0.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1761161130&Signature=wWAfMwSKMBWZyySdnKcMNnEqV3o%3D)

這邊簡單使用`strings`查看裡面有甚麼東西，上網查找發現這是一種叫做`G-code`的東西，專門用來 3D 列印的。

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_735d8d24b2963590589c7c83fef5d05a.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1761161223&Signature=aJauwqwQzEqtaTm5sAOdkLLTpoU%3D)

把這段`G-code`貼到這個網站[NC Viewer](https://ncviewer.com/)就可以拿到答案。

:::flag
AIS3{b4d1y_tun3d_PriN73r}
:::

## Reverse

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_19273c356b29614f48760c726bdf5c18.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1761163178&Signature=CdxwkvhZt0x7hedM0AjPpHedONI%3D)

執行後會有一個地方印 flag 可是印的很慢。

使用 IDA 打開可以看到