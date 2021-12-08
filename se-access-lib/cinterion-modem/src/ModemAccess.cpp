/*
*  PKCS#11 library for IoT Safe
*  Copyright (C) 2007-2009 Gemalto <support@gemalto.com>
*  Copyright (C) 2009-2021 Thales
*
*  This library is free software; you can redistribute it and/or
*  modify it under the terms of the GNU Lesser General Public
*  License as published by the Free Software Foundation; either
*  version 2.1 of the License, or (at your option) any later version.
*
*  This library is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*  Lesser General Public License for more details.
*
*  You should have received a copy of the GNU Lesser General Public
*  License along with this library; if not, write to the Free Software
*  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*
*/
#include <stdio.h>
#include <cstring>

#include "../../iotsafe-middleware/iotsafelib/platform/modem/inc/GenericModem.h"

#define APDURSP_DATA_MAX_SIZE 260

extern "C"
{
#include "../../libse-gto.h"
}

struct se_gto_ctx
{
  char szReaderName[128];
};

GenericModem *modem = nullptr;

using namespace std;

//***Interface libse-gto (C)****//

int se_gto_new(struct se_gto_ctx **ctx)
{
  if (!ctx)
    return -1;

  if (*ctx = new struct se_gto_ctx())
    return 0;
  else
    return -1;
}

void se_gto_set_gtodev(struct se_gto_ctx *ctx, const char *gtodev)
{
  if (!ctx || !gtodev)
    return;

  strcpy(ctx->szReaderName, gtodev);
}

const char* se_gto_get_gtodev(struct se_gto_ctx *ctx)
{
  if (!ctx)
    return NULL;

  return ctx->szReaderName;
}

int se_gto_open(struct se_gto_ctx *ctx)
{
  if (!ctx)
    return -1;

  if (!modem)
  {
    if (!(modem = new GenericModem()))
      return -1;
  }

  if (modem->open(ctx->szReaderName))
    return 0;
  else
    return -1;
}

int se_gto_reset(struct se_gto_ctx *ctx, void *atr, size_t r)
{
  return 0; // Cinterion Modem does not need to be reset.
}

int se_gto_speed(struct se_gto_ctx *ctx, int speed)
{
  return 921600;
}

int se_gto_apdu_transmit(struct se_gto_ctx *ctx, const void *apdu, int n, void *resp, int r)
{
  if (!modem || !ctx || !apdu || !resp)
    return -1;

  uint8_t *_apdu = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(apdu));
  uint8_t *_resp = reinterpret_cast<uint8_t*>(resp);

  uint16_t respLen[APDURSP_DATA_MAX_SIZE];
  memset(respLen, 0x00, APDURSP_DATA_MAX_SIZE);

  if (modem->transmitApdu(_apdu, (uint16_t) n, _resp, respLen) == false)
    return -1;
  else
    return *respLen;
}

int se_gto_close(struct se_gto_ctx *ctx)
{
  if (!modem)
    return -1;

  modem->close();
  delete modem;
  modem = nullptr;

  if (ctx)
    delete ctx;

  return 0;
}
