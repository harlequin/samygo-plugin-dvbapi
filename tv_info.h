/* 
 *  bugficks
 *	(c) 2013
 *
 *  License: GPLv3
 *
 */
//////////////////////////////////////////////////////////////////////////////

#ifndef __TV_INFO_H__
#define __TV_INFO_H__

//////////////////////////////////////////////////////////////////////////////

#include "common.h"

//////////////////////////////////////////////////////////////////////////////

enum eTV_TYPE
{
    TV_TYPE_NON_MST = 0,
    TV_TYPE_MST = 1,
    TV_TYPE_GFS_GFP = 2,
    TV_TYPE_NT = 3,
};

enum eTV_MODEL
{
    TV_MODEL_UNK   = -1,
    TV_MODEL_C     = 0,
    TV_MODEL_D     = 1,
    TV_MODEL_E     = 2,
    TV_MODEL_F     = 3,
    TV_MODEL_H     = 4,
};

inline static int getTVType();
inline static const char *tvTypeToStr(int t);
inline static int getTVModel();
inline static const char *tvModelToStr(int m);

//////////////////////////////////////////////////////////////////////////////

#endif // #ifndef __TV_INFO_H__

//////////////////////////////////////////////////////////////////////////////
