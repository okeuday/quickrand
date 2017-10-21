%-*-Mode:erlang;coding:utf-8;tab-width:4;c-basic-offset:4;indent-tabs-mode:()-*-
% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et nomod:
%%%
%%%------------------------------------------------------------------------
%%% @doc
%%% ==Quick Random Number Generation With Hash Functions==
%%% The random numbers created by the functions in this module are
%%% not meant for cryptographic purposes.
%%%
%%% Any functions that have a jenkins64 prefix use Bob Jenkins' SpookyHash
%%% (SpookyV2, August 5 2012).
%%% @end
%%%
%%% MIT License
%%%
%%% Copyright (c) 2017 Michael Truog <mjtruog at gmail dot com>
%%%
%%% Permission is hereby granted, free of charge, to any person obtaining a
%%% copy of this software and associated documentation files (the "Software"),
%%% to deal in the Software without restriction, including without limitation
%%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%%% and/or sell copies of the Software, and to permit persons to whom the
%%% Software is furnished to do so, subject to the following conditions:
%%%
%%% The above copyright notice and this permission notice shall be included in
%%% all copies or substantial portions of the Software.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%%% DEALINGS IN THE SOFTWARE.
%%%
%%% @author Michael Truog <mjtruog [at] gmail (dot) com>
%%% @copyright 2017 Michael Truog
%%% @version 1.7.3 {@date} {@time}
%%%------------------------------------------------------------------------

-module(quickrand_hash).
-author('mjtruog [at] gmail (dot) com').

%% external interface
-export([jenkins64_128/1,
         jenkins64_128/2,
         jenkins64_64/1,
         jenkins64_64/2,
         jenkins64_32/1,
         jenkins64_32/2]).

% a constant which:
%  * is not zero
%  * is odd
%  * is a not-very-regular mix of 1's and 0's
%  * does not need any other special mathematical properties
-define(JENKINS64_CONST, 16#DEADBEEFDEADBEEF).

%%%------------------------------------------------------------------------
%%% External interface functions
%%%------------------------------------------------------------------------

%%-------------------------------------------------------------------------
%% @doc
%% ===Bob Jenkins SpookyHashV2 Hash128.===
%% @end
%%-------------------------------------------------------------------------

-spec jenkins64_128(MessageRaw :: iodata()) ->
    non_neg_integer().

jenkins64_128(MessageRaw) ->
	jenkins64_128(MessageRaw, 0).

%%-------------------------------------------------------------------------
%% @doc
%% ===Bob Jenkins SpookyHashV2 Hash128.===
%% @end
%%-------------------------------------------------------------------------

-spec jenkins64_128(MessageRaw :: iodata(),
                    Seed :: non_neg_integer()) ->
    non_neg_integer().

jenkins64_128(MessageRaw, Seed)
	when is_integer(Seed), Seed >= 0 ->
    {Message, Size} = iodata_to_list(MessageRaw),
	SeedA = Seed band 16#FFFFFFFFFFFFFFFF,
	SeedB = (Seed bsr 64) band 16#FFFFFFFFFFFFFFFF,
    {HashA, HashB} = jenkins64_128(Message, Size, SeedA, SeedB),
    (HashB bsl 64) + HashA.

%%-------------------------------------------------------------------------
%% @doc
%% ===Bob Jenkins SpookyHashV2 Hash64.===
%% @end
%%-------------------------------------------------------------------------

-spec jenkins64_64(MessageRaw :: iodata()) ->
    non_neg_integer().

jenkins64_64(MessageRaw) ->
	jenkins64_64(MessageRaw, 0).

%%-------------------------------------------------------------------------
%% @doc
%% ===Bob Jenkins SpookyHashV2 Hash64.===
%% @end
%%-------------------------------------------------------------------------

-spec jenkins64_64(MessageRaw :: iodata(),
                   Seed :: non_neg_integer()) ->
    non_neg_integer().

jenkins64_64(MessageRaw, Seed)
	when is_integer(Seed), Seed >= 0 ->
    {Message, Size} = iodata_to_list(MessageRaw),
	SeedA = Seed band 16#FFFFFFFFFFFFFFFF,
    {HashA, _} = jenkins64_128(Message, Size, SeedA, SeedA),
    HashA.

%%-------------------------------------------------------------------------
%% @doc
%% ===Bob Jenkins SpookyHashV2 Hash32.===
%% @end
%%-------------------------------------------------------------------------

-spec jenkins64_32(MessageRaw :: iodata()) ->
    non_neg_integer().

jenkins64_32(MessageRaw) ->
	jenkins64_32(MessageRaw, 0).

%%-------------------------------------------------------------------------
%% @doc
%% ===Bob Jenkins SpookyHashV2 Hash32.===
%% @end
%%-------------------------------------------------------------------------

-spec jenkins64_32(MessageRaw :: iodata(),
                   Seed :: non_neg_integer()) ->
    non_neg_integer().

jenkins64_32(MessageRaw, Seed)
	when is_integer(Seed), Seed >= 0 ->
    {Message, Size} = iodata_to_list(MessageRaw),
	SeedA = Seed band 16#FFFFFFFF,
    {HashA, _} = jenkins64_128(Message, Size, SeedA, SeedA),
    HashA band 16#FFFFFFFF.

%%%------------------------------------------------------------------------
%%% Private functions
%%%------------------------------------------------------------------------

jenkins64_128(Message, Size, SeedA, SeedB) ->
    HashC = ?JENKINS64_CONST,
    HashD = ?JENKINS64_CONST,
	jenkins64_128(Message, Size, SeedA, SeedB, HashC, HashD, Size).

jenkins64_128(Message0, Size0, A0, B0, C0, D0, TotalSize) when Size0 >= 32 ->
    {IncrC, Message1, Size1} = consume_64(Message0, Size0),
    {IncrD, Message2, Size2} = consume_64(Message1, Size1),
    {AN,
     BN,
     CN,
     DN} = jenkins64_short_mix(A0, B0, add_64(C0, IncrC), add_64(D0, IncrD)),
    {IncrA, Message3, Size3} = consume_64(Message2, Size2),
    {IncrB, MessageN, SizeN} = consume_64(Message3, Size3),
	jenkins64_128(MessageN, SizeN,
                  add_64(AN, IncrA), add_64(BN, IncrB), CN, DN, TotalSize);
jenkins64_128(Message0, Size0, A0, B0, C0, D0, TotalSize) when Size0 >= 16 ->
    {IncrC, Message1, Size1} = consume_64(Message0, Size0),
    {IncrD, MessageN, SizeN} = consume_64(Message1, Size1),
    {AN,
     BN,
     CN,
     DN} = jenkins64_short_mix(A0, B0, add_64(C0, IncrC), add_64(D0, IncrD)),
	jenkins64_128(MessageN, SizeN, AN, BN, CN, DN, TotalSize);
jenkins64_128(Message0, Size, AN, BN, C0, D0, TotalSize) when Size >= 12 ->
    D1 = add_64(D0, TotalSize bsl 56),
    [Byte00, Byte01, Byte02, Byte03,
     Byte04, Byte05, Byte06, Byte07, Byte08, Byte09, Byte10, Byte11 |
     Message1] = Message0,
    <<Value64:64/native-unsigned-integer,
      Value32:32/native-unsigned-integer>> =
        <<Byte00, Byte01, Byte02, Byte03,
          Byte04, Byte05, Byte06, Byte07, Byte08, Byte09, Byte10, Byte11>>,
    {ValueByte12, Message3} = if
        Size >= 13 ->
            [Byte12 | Message2] = Message1,
            {Byte12 bsl 32, Message2};
        true ->
            {0, Message1}
    end,
    {ValueByte13, Message5} = if
        Size >= 14 ->
            [Byte13 | Message4] = Message3,
            {Byte13 bsl 40, Message4};
        true ->
            {0, Message3}
    end,
    ValueByte14 = if
        Size == 15 ->
            [Byte14] = Message5,
            Byte14 bsl 48;
        true ->
            [] = Message5,
            0
    end,
    D2 = add_64(D1, ValueByte14),
    D3 = add_64(D2, ValueByte13),
    D4 = add_64(D3, ValueByte12),
    DN = add_64(D4, Value32),
    CN = add_64(C0, Value64),
    jenkins64_short_end(AN, BN, CN, DN);
jenkins64_128(Message0, Size, AN, BN, C0, D0, TotalSize) when Size >=  8 ->
    D1 = add_64(D0, TotalSize bsl 56),
    [Byte00, Byte01, Byte02, Byte03,
     Byte04, Byte05, Byte06, Byte07 | Message1] = Message0,
    <<Value64:64/native-unsigned-integer>> =
        <<Byte00, Byte01, Byte02, Byte03, Byte04, Byte05, Byte06, Byte07>>,
    {ValueByte08, Message3} = if
        Size >= 9 ->
            [Byte08 | Message2] = Message1,
            {Byte08, Message2};
        true ->
            {0, Message1}
    end,
    {ValueByte09, Message5} = if
        Size >= 10 ->
            [Byte09 | Message4] = Message3,
            {Byte09 bsl 8, Message4};
        true ->
            {0, Message3}
    end,
    ValueByte10 = if
        Size == 11 ->
            [Byte10] = Message5,
            Byte10 bsl 16;
        true ->
            [] = Message5,
            0
    end,
    D2 = add_64(D1, ValueByte10),
    D3 = add_64(D2, ValueByte09),
    DN = add_64(D3, ValueByte08),
    CN = add_64(C0, Value64),
    jenkins64_short_end(AN, BN, CN, DN);
jenkins64_128(Message0, Size, AN, BN, C0, D0, TotalSize) when Size >=  4 ->
    DN = add_64(D0, TotalSize bsl 56),
    [Byte00, Byte01, Byte02, Byte03 | Message1] = Message0,
    <<Value32:32/native-unsigned-integer>> =
        <<Byte00, Byte01, Byte02, Byte03>>,
    {ValueByte04, Message3} = if
        Size >= 5 ->
            [Byte04 | Message2] = Message1,
            {Byte04 bsl 32, Message2};
        true ->
            {0, Message1}
    end,
    {ValueByte05, Message5} = if
        Size >= 6 ->
            [Byte05 | Message4] = Message3,
            {Byte05 bsl 40, Message4};
        true ->
            {0, Message3}
    end,
    ValueByte06 = if
        Size == 7 ->
            [Byte06] = Message5,
            Byte06 bsl 48;
        true ->
            [] = Message5,
            0
    end,
    C1 = add_64(C0, ValueByte06),
    C2 = add_64(C1, ValueByte05),
    C3 = add_64(C2, ValueByte04),
    CN = add_64(C3, Value32),
    jenkins64_short_end(AN, BN, CN, DN);
jenkins64_128(Message0, Size, AN, BN, C0, D0, TotalSize) when Size >=  1 ->
    DN = add_64(D0, TotalSize bsl 56),
    [Byte00 | Message1] = Message0,
    {ValueByte01, Message3} = if
        Size >= 2 ->
            [Byte01 | Message2] = Message1,
            {Byte01 bsl 8, Message2};
        true ->
            {0, Message1}
    end,
    ValueByte02 = if
        Size == 3 ->
            [Byte02] = Message3,
            Byte02 bsl 16;
        true ->
            [] = Message3,
            0
    end,
    C1 = add_64(C0, ValueByte02),
    C2 = add_64(C1, ValueByte01),
    CN = add_64(C2, Byte00),
    jenkins64_short_end(AN, BN, CN, DN);
jenkins64_128([], 0, AN, BN, C0, D0, TotalSize) ->
    D1 = add_64(D0, TotalSize bsl 56),
    CN = add_64(C0, ?JENKINS64_CONST),
    DN = add_64(D1, ?JENKINS64_CONST),
    jenkins64_short_end(AN, BN, CN, DN).

%
% The goal is for each bit of the input to expand into 128 bits of 
%   apparent entropy before it is fully overwritten.
% n trials both set and cleared at least m bits of h0 h1 h2 h3
%   n: 2   m: 29
%   n: 3   m: 46
%   n: 4   m: 57
%   n: 5   m: 107
%   n: 6   m: 146
%   n: 7   m: 152
% when run forwards or backwards
% for all 1-bit and 2-bit diffs
% with diffs defined by either xor or subtraction
% with a base of all zeros plus a counter, or plus another bit, or random
%
jenkins64_short_mix(H0_0, H1_0, H2_0, H3_0)
    when is_integer(H0_0), is_integer(H1_0),
         is_integer(H2_0), is_integer(H3_0) ->
    H2_1 = add_64(rotate_64(H2_0, 50), H3_0),H0_1 = H0_0 bxor H2_1,
    H3_1 = add_64(rotate_64(H3_0, 52), H0_1),H1_1 = H1_0 bxor H3_1,
    H0_2 = add_64(rotate_64(H0_1, 30), H1_1),H2_2 = H2_1 bxor H0_2,
    H1_2 = add_64(rotate_64(H1_1, 41), H2_2),H3_2 = H3_1 bxor H1_2,
    H2_3 = add_64(rotate_64(H2_2, 54), H3_2),H0_3 = H0_2 bxor H2_3,
    H3_3 = add_64(rotate_64(H3_2, 48), H0_3),H1_3 = H1_2 bxor H3_3,
    H0_4 = add_64(rotate_64(H0_3, 38), H1_3),H2_4 = H2_3 bxor H0_4,
    H1_4 = add_64(rotate_64(H1_3, 37), H2_4),H3_4 = H3_3 bxor H1_4,
    H2_5 = add_64(rotate_64(H2_4, 62), H3_4),H0_5 = H0_4 bxor H2_5,
    H3_5 = add_64(rotate_64(H3_4, 34), H0_5),H1_5 = H1_4 bxor H3_5,
    H0_N = add_64(rotate_64(H0_5,  5), H1_5),H2_N = H2_5 bxor H0_N,
    H1_N = add_64(rotate_64(H1_5, 36), H2_N),H3_N = H3_5 bxor H1_N,
    {H0_N, H1_N, H2_N, H3_N}.

%
% Mix all 4 inputs together so that h0, h1 are a hash of them all.
%
% For two inputs differing in just the input bits
% Where "differ" means xor or subtraction
% And the base value is random, or a counting value starting at that bit
% The final result will have each bit of h0, h1 flip
% For every input bit,
% with probability 50 +- .3% (it is probably better than that)
% For every pair of input bits,
% with probability 50 +- .75% (the worst case is approximately that)
%
jenkins64_short_end(H0_0, H1_0, H2_0, H3_0)
    when is_integer(H0_0), is_integer(H1_0),
         is_integer(H2_0), is_integer(H3_0) ->
    H3_1 = H3_0 bxor H2_0,H2_1 = rotate_64(H2_0, 15),H3_2 = add_64(H3_1, H2_1),
    H0_1 = H0_0 bxor H3_2,H3_3 = rotate_64(H3_2, 52),H0_2 = add_64(H0_1, H3_3),
    H1_1 = H1_0 bxor H0_2,H0_3 = rotate_64(H0_2, 26),H1_2 = add_64(H1_1, H0_3),
    H2_2 = H2_1 bxor H1_2,H1_3 = rotate_64(H1_2, 51),H2_3 = add_64(H2_2, H1_3),
    H3_4 = H3_3 bxor H2_3,H2_4 = rotate_64(H2_3, 28),H3_5 = add_64(H3_4, H2_4),
    H0_4 = H0_3 bxor H3_5,H3_6 = rotate_64(H3_5,  9),H0_5 = add_64(H0_4, H3_6),
    H1_4 = H1_3 bxor H0_5,H0_6 = rotate_64(H0_5, 47),H1_5 = add_64(H1_4, H0_6),
    H2_5 = H2_4 bxor H1_5,H1_6 = rotate_64(H1_5, 54),H2_6 = add_64(H2_5, H1_6),
    H3_7 = H3_6 bxor H2_6,H2_N = rotate_64(H2_6, 32),H3_8 = add_64(H3_7, H2_N),
    H0_7 = H0_6 bxor H3_8,H3_N = rotate_64(H3_8, 25),H0_8 = add_64(H0_7, H3_N),
    H1_7 = H1_6 bxor H0_8,H0_N = rotate_64(H0_8, 63),H1_N = add_64(H1_7, H0_N),
    {H0_N, H1_N}.

% left rotate a 64-bit value by k bits
rotate_64(X, Bits)
    when is_integer(X), is_integer(Bits), Bits >= 0, Bits =< 64 ->
    ((X bsl Bits) band 16#FFFFFFFFFFFFFFFF) bor (X bsr (64 - Bits)).

consume_64([Byte00, Byte01, Byte02, Byte03, Byte04, Byte05, Byte06, Byte07 |
            Message], Size) ->
    <<Value:64/native-unsigned-integer>> =
        <<Byte00, Byte01, Byte02, Byte03, Byte04, Byte05, Byte06, Byte07>>,
    {Value, Message, Size - 8}.

add_64(X, Y)
    when is_integer(X), is_integer(Y) ->
	(X + Y) band 16#FFFFFFFFFFFFFFFF.

iodata_to_list(IOData) ->
    iodata_to_list([], IOData, 0).

iodata_to_list(ListOut, IODataIn, Size)
    when is_binary(IODataIn) ->
    iodata_to_list(lists:reverse(erlang:binary_to_list(IODataIn), ListOut),
                   [], Size + byte_size(IODataIn));
iodata_to_list(ListOut, [Binary | IODataIn], Size)
    when is_binary(Binary) ->
    iodata_to_list(lists:reverse(erlang:binary_to_list(Binary), ListOut),
                   IODataIn, Size + byte_size(Binary));
iodata_to_list(ListOut0, [List | IODataIn], Size0)
    when is_list(List) ->
    {ListOutN, SizeN} = iodata_to_list(ListOut0, List, Size0),
    iodata_to_list(lists:reverse(ListOutN), IODataIn, SizeN);
iodata_to_list(ListOut, [], Size) ->
    {lists:reverse(ListOut), Size};
iodata_to_list(ListOut, [Byte | IOData], Size)
    when is_integer(Byte), Byte >= 0, Byte =< 255 ->
    iodata_to_list([Byte | ListOut], IOData, Size + 1);
iodata_to_list(ListOut, Byte, Size)
    when is_integer(Byte), Byte >= 0, Byte =< 255 ->
    {lists:reverse([Byte | ListOut]), Size + 1}.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

jenkins64_test() ->
    Message1 = "The quick brown fox jumps over the lazy dog",
    Hash1_32 = 2852557767,
    Hash1_64 = 3103798483409605575,
    Hash1_128 = 38830560693350521669816352328101827527,
    Hash1_32 = quickrand_hash:jenkins64_32(Message1),
    Hash1_64 = quickrand_hash:jenkins64_64(Message1),
    Hash1_128 = quickrand_hash:jenkins64_128(Message1),
    ok.

-endif.
