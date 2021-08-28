/*
 * MIT License
 *
 * Copyright 2021 Myndigheten för digital förvaltning (DIGG)
 */
package se.digg.dgc.service.impl;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.UUID;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import se.digg.dgc.encoding.Barcode;
import se.digg.dgc.encoding.impl.DefaultBarcodeCreator;
import se.digg.dgc.encoding.impl.DefaultBarcodeDecoder;
import se.digg.dgc.payload.v1.DigitalCovidCertificate;
import se.digg.dgc.payload.v1.PersonName;
import se.digg.dgc.payload.v1.VaccinationEntry;
import se.digg.dgc.signatures.impl.DefaultDGCSignatureVerifier;
import se.digg.dgc.signatures.impl.DefaultDGCSigner;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Test cases for {@link DefaultDGCBarcodeEncoder}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Henrik Bengtsson (extern.henrik.bengtsson@digg.se)
 * @author Henric Norlander (extern.henric.norlander@digg.se)
 */
public class DefaultDGCBarcodeEncoderDecoderTest {

  private PkiCredential ecdsa;

  private static final char[] password = "secret".toCharArray();

  public DefaultDGCBarcodeEncoderDecoderTest() throws Exception {
    this.ecdsa = new KeyStoreCredential(new ClassPathResource("ecdsa.jks"), password, "signer", password);
    this.ecdsa.init();
  }

  @Test
  public void testEncodeDecodeBarcode() throws Exception {

    final Instant expire = Instant.now().plus(Duration.ofDays(30));
    final DigitalCovidCertificate dgc = getTestDGC();

    final DefaultDGCBarcodeEncoder encoder = new DefaultDGCBarcodeEncoder(new DefaultDGCSigner(this.ecdsa), new DefaultBarcodeCreator());

    final Barcode barcode = encoder.encodeToBarcode(dgc, expire);

    final DefaultDGCBarcodeDecoder decoder = new DefaultDGCBarcodeDecoder(
      new DefaultDGCSignatureVerifier(), (x,y) -> Arrays.asList(this.ecdsa.getCertificate().getPublicKey()), new DefaultBarcodeDecoder());

    final DigitalCovidCertificate dgc2 = decoder.decodeBarcode(barcode.getImage());
    Assert.assertEquals(dgc, dgc2);
    Assert.assertEquals("KARL<MAARTEN", dgc2.getNam().getGnt());
    Assert.assertEquals("LINDSTROEM", dgc2.getNam().getFnt());
  }

  private DigitalCovidCertificate getTestDGC() {
    DigitalCovidCertificate dgc = new DigitalCovidCertificate();
    dgc.setVer("1.0.0");

    dgc.setNam(new PersonName().withGn("Karl Mårten").withFn("Lindström"));
    dgc.setDob(LocalDate.parse("1969-11-29"));


    VaccinationEntry vac = new VaccinationEntry();
    vac
      .withCi(UUID.randomUUID().toString())
      .withTg("840539006")
      .withDt(LocalDate.parse("2021-04-02"))
      .withCo("SE")
      .withDn(Integer.valueOf(1))
      .withSd(Integer.valueOf(2))
      .withIs("eHälsomyndigheten")
      .withMa("ORG-100001699")
      .withMp("CVnCoV")
      .withVp("1119349007");

    dgc.setV(Arrays.asList(vac));

    return dgc;
  }

}
